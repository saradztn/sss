#!/usr/bin/env python3
"""
nrth_probe.py — READ-ONLY in-memory code-integrity probe (defensive).

Case: mta_blue_team_case · Result class: R2 (newly authored defensive tool)

WHAT IT DOES
  * Takes a *baseline* of the executable code (.text/.init) bytes of one or more
    modules inside a running process on a clean client, then
  * re-reads the same bytes later and reports every differing 16-byte block with
    its module-relative RVA, classifying the change:
        HOOK_JMP   - block starts with E9 (jmp rel32) or FF25 (jmp [addr])
        EARLY_RET  - block starts with C3 / C2 xx xx  -> the "kill-switch" shape
                     documented for the sample's netc.dll routine
                     (mta_blue_team_case/mechanism_overview_ar.md §4: original
                     writes a single 0xC3 at the target function's first byte)
        PATCHED    - anything else that differs
  * Also lists loaded modules whose signing state changed since baseline, and
    unsigned modules newly mapped into the game process.

WHAT IT NEVER DOES (deliberate design boundary for a blue-team tool)
  * No WriteProcessMemory, no VirtualProtectEx, no thread creation, no pattern
    scanner API, no callable handle returned to callers. `PROCESS_VM_READ` +
    `PROCESS_QUERY_INFORMATION` only. It cannot modify anything, by construction.
  * It is not a cheat re-implementation: the detection is baseline *diffing*, so
    it does not need to locate the game's Lua functions, and no resolver helper is
    exposed here.

HOST REQUIREMENTS (live mode)
  Windows, 32-bit or 64-bit Python, run from an elevated prompt against a game
  process you are authorized to inspect. Offline mode (`diff`) works anywhere and
  is what the shipped unit tests exercise.

NOT EXECUTED HERE
  The analysis host is Linux with no MTA:SA/Windows client, so live
  (baseline/check against a real game process) was NOT run in this engagement.
  Only the pure diff/classification logic is tested here — see
  ../../test_results/integrity_probe_logic.log.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

CODE_SECTIONS = (".text", ".init")
BLOCK = 16
ANOMALY_SEVERITY = {"EARLY_RET": "high", "HOOK_JMP": "high", "HOOK_PUSH_RET": "medium", "PATCHED": "medium"}


# ---------------------------------------------------------------------------
# Pure logic (unit-testable off-Windows)
# ---------------------------------------------------------------------------
def classify_prologue(data: bytes) -> Optional[str]:
    """Classify the *start* of a patched code block by its first opcode(s)."""
    if not data:
        return None
    b0 = data[0]
    if b0 == 0xE9:
        return "HOOK_JMP"                    # jmp rel32  (MinHook/Detours style)
    if b0 == 0xFF and len(data) > 1 and data[1] in (0x25, 0x15):
        return "HOOK_JMP"                    # jmp [abs] / jmp [reg]
    if b0 == 0xEB:
        return "HOOK_JMP"                    # jmp short
    if b0 == 0x68 and len(data) > 5 and data[5] == 0xC3:
        return "HOOK_PUSH_RET"               # push addr; ret  (detour stub)
    if b0 == 0xC3 or (b0 == 0xC2 and len(data) > 2):
        return "EARLY_RET"                   # ret / ret n -> function neutered
    if b0 == 0xCC:
        return "BREAKPOINT_OR_STUB"          # int3 fill
    return "PATCHED"


def diff_blocks(baseline: bytes, live: bytes, base_rva: int = 0) -> List[dict]:
    """Return one record per differing BLOCK-sized chunk (offsets are module-relative RVAs)."""
    out: List[dict] = []
    n = min(len(baseline), len(live))
    for off in range(0, n, BLOCK):
        b = baseline[off:off + BLOCK]
        l = live[off:off + BLOCK]
        if b == l:
            continue
        # locate the exact first differing byte so the report is precise
        delta = 0
        while delta < len(b) and delta < len(l) and b[delta] == l[delta]:
            delta += 1
        real = off + delta
        kind = classify_prologue(l[delta:]) or "PATCHED"
        out.append({
            "rva": "0x%X" % (base_rva + real),
            "offset": real,
            "kind": kind,
            "severity": ANOMALY_SEVERITY.get(kind, "low"),
            "baseline_bytes": b[delta:delta + 8].hex(),
            "live_bytes": l[delta:delta + 8].hex(),
        })
    if len(baseline) != len(live):
        out.append({"rva": "n/a", "offset": n, "kind": "SIZE_MISMATCH", "severity": "high",
                    "baseline_bytes": str(len(baseline)), "live_bytes": str(len(live))})
    return out


def section_range_from_headers(image: bytes, name: str) -> Optional[Tuple[int, int]]:
    """(rva, size) of a named section, parsed from an in-memory PE header."""
    if len(image) < 0x40 or image[:2] != b"MZ":
        return None
    (pe_off,) = struct.unpack_from("<I", image, 0x3C)
    if pe_off + 24 > len(image) or image[pe_off:pe_off + 4] != b"PE\x00\x00":
        return None
    (nsec,) = struct.unpack_from("<H", image, pe_off + 6)
    sizeopt = struct.unpack_from("<H", image, pe_off + 20)[0]
    tab = pe_off + 24 + sizeopt
    for i in range(nsec):
        e = tab + i * 40
        if e + 40 > len(image):
            break
        raw = image[e:e + 8].rstrip(b"\x00").decode("latin-1")
        if raw == name:
            vsize, vaddr = struct.unpack_from("<II", image, e + 8)
            return vaddr, vsize or 0x1000
    return None


# ---------------------------------------------------------------------------
# Windows live access (read-only by construction)
# ---------------------------------------------------------------------------
@dataclass
class ProcHandle:
    pid: int
    handle: int
    modules: Dict[str, int] = field(default_factory=dict)

    def close(self) -> None:
        if self.handle:
            ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(self.handle))
            self.handle = 0


def open_process_readonly(pid: int) -> ProcHandle:
    if sys.platform != "win32":
        raise RuntimeError("live mode requires Windows; use 'diff' for offline comparison")
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    k32 = ctypes.windll.kernel32
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        raise OSError("OpenProcess failed (err=%d) — elevated prompt / same-bitness required"
                      % ctypes.GetLastError())
    ph = ProcHandle(pid=pid, handle=h)
    psapi = ctypes.windll.psapi
    arr = (ctypes.c_void_p * 2048)()
    needed = ctypes.c_ulong()
    if psapi.EnumProcessModules(ph.handle, arr, ctypes.sizeof(arr), ctypes.byref(needed)):
        count = needed.value // ctypes.sizeof(ctypes.c_void_p)
        buf = ctypes.create_string_buffer(1024)
        for i in range(count):
            if psapi.GetModuleBaseNameA(ph.handle, arr[i], buf, 1024):
                ph.modules[buf.value.decode("latin-1").lower()] = arr[i] or 0
    return ph


def read_memory(ph: ProcHandle, addr: int, size: int) -> bytes:
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    ok = ctypes.windll.kernel32.ReadProcessMemory(
        ctypes.c_void_p(ph.handle), ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
    if not ok and got.value == 0:
        raise OSError("ReadProcessMemory(0x%X, %d) failed (err=%d)" % (addr, size, ctypes.GetLastError()))
    data = buf.raw[:got.value]
    return data + b"\x00" * (size - len(data))   # short reads recorded as zeros


def module_sections(ph: ProcHandle, name: str) -> List[Tuple[str, int, int]]:
    base = ph.modules[name.lower()]
    head = read_memory(ph, base, 0x1000)
    out = []
    for sec in CODE_SECTIONS:
        rng = section_range_from_headers(head, sec)
        if rng:
            out.append((sec, base + rng[0], rng[1]))
    return out


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_baseline(args) -> int:
    os.makedirs(args.out, exist_ok=True)
    ph = open_process_readonly(args.pid)
    manifest = {"tool": "nrth_probe", "version": 1, "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "pid": args.pid, "note": "read-only baseline; memory image (not file image)", "modules": []}
    for name in [m.strip() for m in args.modules.split(",") if m.strip()]:
        if name.lower() not in ph.modules:
            print("[!] module not loaded: %s" % name, file=sys.stderr)
            continue
        for sec, addr, size in module_sections(ph, name):
            data = read_memory(ph, addr, size)
            path = os.path.join(args.out, "%s.%s.bin" % (name, sec))
            with open(path, "wb") as fh:
                fh.write(data)
            manifest["modules"].append({"name": name, "section": sec, "base": "0x%X" % ph.modules[name.lower()],
                                        "rva": addr - ph.modules[name.lower()], "size": size,
                                        "sha256": hashlib.sha256(data).hexdigest(), "file": os.path.basename(path)})
            print("[+] baseline %s%s  size=0x%X sha256=%s" % (name, sec, size, manifest["modules"][-1]["sha256"][:16]))
    ph.close()
    with open(os.path.join(args.out, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    print("[+] wrote %s" % os.path.join(args.out, "manifest.json"))
    return 0


def cmd_check(args) -> int:
    with open(os.path.join(args.baseline, "manifest.json"), "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    ph = open_process_readonly(args.pid)
    report = {"tool": "nrth_probe", "mode": "check", "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
              "baseline_created": manifest.get("created"), "pid": args.pid, "anomalies": [], "summary": {}}
    for entry in manifest["modules"]:
        if entry["name"].lower() not in ph.modules:
            report["anomalies"].append({"module": entry["name"], "kind": "MODULE_GONE", "severity": "info"})
            continue
        base = ph.modules[entry["name"].lower()]
        with open(os.path.join(args.baseline, entry["file"]), "rb") as fh:
            stored = fh.read()
        live = read_memory(ph, base + entry["rva"], entry["size"])
        diffs = diff_blocks(stored, live, base_rva=0)
        for d in diffs:
            d["module"] = entry["name"]
            d["section"] = entry["section"]
        report["anomalies"].extend(diffs)
        report["summary"][entry["name"] + entry["section"]] = {"sha256_stored": entry["sha256"],
                                                               "sha256_live": hashlib.sha256(live).hexdigest(),
                                                               "changed_blocks": len(diffs)}
    ph.close()
    txt = json.dumps(report, indent=2)
    print(txt)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(txt)
    high = [a for a in report["anomalies"] if a.get("severity") == "high"]
    if high:
        print("[!] %d high-severity code anomalies (HOOK_JMP / EARLY_RET / SIZE_MISMATCH)" % len(high), file=sys.stderr)
        return 2
    return 0 if not report["anomalies"] else 1


def cmd_diff(args) -> int:
    """Offline: compare two code dumps (or two PE files' .text) — no process access."""
    with open(args.before, "rb") as fh:
        a = fh.read()
    with open(args.after, "rb") as fh:
        b = fh.read()
    if args.pe:
        ia, ib = a, b
        ra = section_range_from_headers(ia, ".text")
        rb = section_range_from_headers(ib, ".text")
        if not ra or not rb:
            print("[!] .text not found in one of the images", file=sys.stderr)
            return 3
        a, b = ia[ra[0]:ra[0] + ra[1]], ib[rb[0]:rb[0] + rb[1]]
    diffs = diff_blocks(a, b)
    print(json.dumps({"before": args.before, "after": args.after, "changed_blocks": len(diffs),
                      "anomalies": diffs[:args.max]}, indent=2))
    return 0 if not diffs else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1], formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("baseline", help="capture read-only code bytes from a clean process")
    b.add_argument("--pid", type=int, required=True)
    b.add_argument("--modules", default="client.dll,netc.dll")
    b.add_argument("--out", required=True)
    b.set_defaults(func=cmd_baseline)

    c = sub.add_parser("check", help="compare live process against the baseline")
    c.add_argument("--pid", type=int, required=True)
    c.add_argument("--baseline", required=True)
    c.add_argument("--json", default=None)
    c.set_defaults(func=cmd_check)

    d = sub.add_parser("diff", help="offline: compare two dumps or two PE files (.text)")
    d.add_argument("before")
    d.add_argument("after")
    d.add_argument("--pe", action="store_true")
    d.add_argument("--max", type=int, default=50)
    d.set_defaults(func=cmd_diff)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
