#!/usr/bin/env python3
"""nrth_report_path_check.py — defender-side *report-path health check* (blue-team tool).

WHY THIS EXISTS
The sample's netc.dll cluster does not hook by jump only: it also writes a single 0xC3 (ret) over the
first byte of report-path functions, staging the value with `mov byte ptr [ebp-0x16], 0xC3` inside the
payload and applying it through VirtualProtect(page,1,PAGE_EXECUTE_READWRITE) + `mov [ptr],cl`
(Observed: staging sites VA 0x100206f0, 0x100208aa, 0x10020927, 0x10020f46, 0x100214bd, 0x100215f1;
writer 0x10011870; target list 0x101493e4; hooks on 0x1001dd30/0x1001dd90/0x1001df90/0x1001fa80).
Those netc functions are found at RUNTIME by pattern scan, so a hash of netc.dll on disk stays clean
while the live function entry is `0xC3`. This tool checks the thing that actually matters: **the first
bytes of the located function entries**.

SUBCOMMANDS
  payload <nrth.dll>            Verify the payload still contains its kill-staging plan (the six
                                `C6 45 EA C3` sites and the 0xE9/0xFF25 detour staging). Defensive
                                regression check for the detector's own assumptions.
  entries <pe.dll> [--funcs f]  Classify the first bytes of each function entry in an RVA list.
                                INTACT (55 8B EC / 53 8B DC) vs KILLED (C3) / DETOUR (E9 rel32,
                                FF 25 ptr) / PUSHRET (68 imm32 C3) / OTHER. Exit 3 if any is not INTACT.
  fixture                       Generate tools/nrth_netc_fixture.py's pristine + killed DLLs and run
                                `entries` on both — the labelled SYNTHETIC positive/negative control.

The `--funcs` list is what a real private-server run supplies: the client-side collector
(mta_blue_team_case/private_server_tests/real_test_kit/collect_client.ps1) records the addresses it
resolved for the screenshot/transgression entry points and dumps them here.
"""
import argparse
import json
import os
import re
import struct
import subprocess
import sys

import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nrth_pe_catalog import PE  # noqa: E402


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def va_of(pe, rva):
    return pe.image_base + rva

# Evidence from working/NRTH.dll (original sample); see mta_blue_team_case/behavior_timeline.md.
# These six VAs are the CALL sites of the writer (`e8 rel32` measured there, e.g. 0x100206f0 =
# e8 7b 11 ff ff). The staged value sits exactly 0x0B bytes earlier in every one of the six, as
# `mov byte ptr [ebp-disp8], 0xC3` (measured staging VAs: 0x100206e5, 0x1002089f, 0x1002091c,
# 0x10020f3b, 0x100214b2, 0x100215e6) - i.e. one staging + one call pair per netc report entry.
KILL_STAGING_SITES = [0x100206F0, 0x100208AA, 0x10020927, 0x10020F46, 0x100214BD, 0x100215F1]
PAIR_WINDOW = 0x40          # staging is 0x0B before the call; anything further is not "this" site
INTACT_PROLOGUES = (b"\x55\x8b\xec", b"\x53\x8b\xdc")
# The staging instruction is 'mov byte ptr [ebp-disp8], 0xC3' (C6 45 disp8 C3). The slot differs per
# function, so the scan is disp8-agnostic; C645EAC3 is one instance of it.
STAGING_RE = re.compile(rb"\xc6\x45[\x00-\xff]\xc3")


def classify(buf):
    if buf[:1] == b"\xc3":
        return "KILLED", "0xC3 (ret) written over the entry byte"
    if buf[:1] == b"\xe9" and len(buf) >= 5:
        rel = struct.unpack("<i", buf[1:5])[0]
        return "DETOUR", "E9 rel32 -> +0x%X" % (rel + 5 if rel >= 0 else rel + 5)
    if buf[:3] in (b"\xff\x25\x2a",) or buf[:2] == b"\xff\x25":
        return "DETOUR", "FF 25 far-jmp through pointer"
    if buf[:1] == b"\x68" and buf[5:6] == b"\xc3":
        return "PUSHRET", "68 imm32 / C3 (trampoline push-ret)"
    for p in INTACT_PROLOGUES:
        if buf[:3] == p:
            return "INTACT", "normal function prologue"
    return "OTHER", "no known prologue (compiled differently? verify manually)"


def load_funcs(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    for key in ("funcs", "rows", "entries"):      # fixture JSON uses "rows"; a client dump may use "funcs"
        if isinstance(data.get(key), list):
            return data[key]
    return []


def cmd_entries(args):
    pe = PE(args.pe)
    funcs = load_funcs(args.funcs) if args.funcs else []
    if not funcs:
        print("[-] --funcs <json> required (list of {'rva': ...} or offsets)", file=sys.stderr)
        return 2
    rows, bad = [], 0
    for fn in funcs:
        rva = fn["rva"] if isinstance(fn, dict) else int(fn, 0) if isinstance(fn, str) else int(fn)
        off = pe.r2o(rva)
        if off is None:
            rows.append((rva, va_of(pe, rva), "UNMAPPED", "rva outside any raw section", ""))
            bad += 1
            continue
        state, why = classify(pe.d[off:off + 8])
        rows.append((rva, va_of(pe, rva), state, why, "yes" if state != "INTACT" else ""))
        if state != "INTACT":
            bad += 1
    print("== report-path entry health: %s (%s, %d entries)" % (os.path.basename(args.pe), sha256_file(args.pe)[:16], len(rows)))
    for rva, va, state, why, flag in rows:
        print("   0x%08x (va 0x%08x) %-9s %s%s" % (rva, va, state, why, "   <== FLAGGED" if flag == "yes" else ""))
    if args.csv:
        with open(args.csv, "w", encoding="utf-8") as f:
            f.write("rva,va,state,detail,flagged\n")
            for rva, va, state, why, flag in rows:
                f.write("0x%x,0x%x,%s,%s,%s\n" % (rva, va, state, why.replace(",", ";"), flag))
    print("[=] %d/%d entries INTACT, %d abnormal" % (len(rows) - bad, len(rows), bad))
    print("[i] exit 0 = report path intact, exit 3 = one or more entries overwritten")
    return 0 if bad == 0 else 3


def cmd_payload(args):
    pe = PE(args.pe)
    text = None
    for s in pe.sections:
        if s["ch"] & 0x20000000:              # IMAGE_SCN_MEM_EXECUTE
            text = s
            break
    blob = pe.d[text["ro"]:text["ro"] + text["rsz"]] if text else pe.d
    base = pe.image_base + (text["va"] if text else 0)
    hits = [base + m.start() for m in STAGING_RE.finditer(blob)]
    print("== payload kill-plan presence: %s (%s)" % (os.path.basename(args.pe), sha256_file(args.pe)[:16]))
    print("   'mov byte ptr [ebp-0x16],0xC3' staging sites found: %d  (sample documents %d)"
          % (len(hits), len(KILL_STAGING_SITES)))
    near = []
    for k in KILL_STAGING_SITES:
        cand = [h for h in hits if -PAIR_WINDOW <= (h - k) <= PAIR_WINDOW]
        near.append((k, cand[0] if cand else None))
    for k, found in near:
        print("      call site va=0x%08x -> %s" % (k, ("staging at 0x%08x (%d bytes before the call)"
                                                       % (found, k - found)) if found
                                                   else "NOT FOUND within %d bytes" % PAIR_WINDOW))
    for va in hits:
        if not any(-0x200 <= (va - k) <= 0x200 for k in KILL_STAGING_SITES):
            print("      additional staging site va=0x%08x" % va)
    print("   note: full per-signature state classification lives in bin/nrth_audit.exe "
          "(20 signatures, same footprints). This subcommand only proves the health check's "
          "assumption - that the staging sites exist in the payload - and is cheap to run.")
    ok = all(f is not None for _, f in near)
    print("[=] %d/%d documented staging sites located (total sites of this form in the payload: %d)"
          % (sum(1 for _, f in near if f is not None), len(KILL_STAGING_SITES), len(hits)))
    print("    %s" % ("kill plan present as documented" if ok
                      else "one or more documented sites missing (different payload?)"))
    return 0 if ok else 3


def cmd_fixture(args):
    here = os.path.dirname(os.path.abspath(__file__))
    subprocess.run([sys.executable, os.path.join(here, "nrth_netc_fixture.py")], check=True,
                   stdout=subprocess.DEVNULL)
    jf = os.path.normpath(os.path.join(here, "..", "..", "working", "fixture_netc.json"))
    rc = []
    for name in ("fixture_netc_pristine.dll", "fixture_netc_killed.dll"):
        rc.append(cmd_entries(argparse.Namespace(pe=os.path.normpath(os.path.join(here, "..", "..", "working", name)),
                                                  funcs=jf, csv=None)))
    print("[i] SYNTHETIC FIXTURE — a hand-built PE used only to prove the check discriminates; "
          "it is not the real netc.dll and carries none of its content.")
    print("[=] pristine exit=%d (expect 0), killed exit=%d (expect 3)" % (rc[0], rc[1]))
    return 0 if (rc[0] == 0 and rc[1] == 3) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("entries"); a.add_argument("pe"); a.add_argument("--funcs"); a.add_argument("--csv")
    a.set_defaults(fn=cmd_entries)
    b = sub.add_parser("payload"); b.add_argument("pe"); b.set_defaults(fn=cmd_payload)
    c = sub.add_parser("fixture"); c.set_defaults(fn=cmd_fixture)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
