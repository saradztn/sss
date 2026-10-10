#!/usr/bin/env python3
"""
test_probe_logic.py — unit tests for nrth_probe's pure logic (offline, any OS).

Run:  python3 test_probe_logic.py            (exit 0 = all pass)
Scope note: these tests validate the *detection* logic of the defensive probe.
They are not evidence about live Windows behaviour (no Windows/MTA client was
available on the analysis host) and not evidence about the original sample.
"""
import json
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import nrth_probe as P  # noqa: E402

FAIL = []
PASS = 0


def check(name, cond, extra=""):
    global PASS
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name, (" :: " + str(extra)) if (extra and not cond) else ""))
    if cond:
        PASS += 1
    else:
        FAIL.append(name)


def fake_pe(text_rva=0x2000, text_size=0x200, with_text=True):
    """Minimal PE header (PE32) with an optional .text entry, for header parsing tests."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = bytearray(b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14C, 1, 0, 0x1000, 0x2000, 0xE0, 0x0102))
    opt = bytearray(0xE0)
    sec = bytearray(40)
    if with_text:
        sec[0:6] = b".text\x00"
        struct.pack_into("<II", sec, 8, text_size, text_rva)
    image = bytes(dos) + bytes(coff) + bytes(opt) + bytes(sec)
    return image + b"\x90" * 0x200


print("== nrth_probe logic tests ==")

# classify_prologue
check("E9 -> HOOK_JMP", P.classify_prologue(b"\xe9\x11\x22\x33\x44") == "HOOK_JMP")
check("FF25 -> HOOK_JMP", P.classify_prologue(b"\xff\x25\x78\x56\x34\x12") == "HOOK_JMP")
check("EB (short jmp) -> HOOK_JMP", P.classify_prologue(b"\xeb\xfe") == "HOOK_JMP")
check("C3 -> EARLY_RET (netc kill-switch shape)", P.classify_prologue(b"\xc3\x90\x90") == "EARLY_RET")
check("C2 04 00 -> EARLY_RET", P.classify_prologue(b"\xc2\x04\x00") == "EARLY_RET")
check("push addr; ret -> HOOK_PUSH_RET", P.classify_prologue(b"\x68\x11\x22\x33\x44\xc3") == "HOOK_PUSH_RET")
check("CC -> BREAKPOINT_OR_STUB", P.classify_prologue(b"\xcc\xcc") == "BREAKPOINT_OR_STUB")
check("90 -> PATCHED", P.classify_prologue(b"\x90\x90") == "PATCHED")
check("empty -> None", P.classify_prologue(b"") is None)

# diff_blocks
base = bytearray(b"\x55\x8b\xec" * 40)          # 120 bytes
live = bytearray(base)
check("identical images -> no anomalies", P.diff_blocks(bytes(base), bytes(live)) == [])

live = bytearray(base)
live[0x1A] = 0xE9                                # jmp hook 4 bytes past a block start
res = P.diff_blocks(bytes(base), bytes(live))
check("one differing byte -> exactly one block record", len(res) == 1, res)
check("offset points at the first changed byte", res and res[0]["offset"] == 0x1A, res)
check("RVA reported as hex string", res and res[0]["rva"] == "0x1A", res)
check("classification = HOOK_JMP", res and res[0]["kind"] == "HOOK_JMP", res)
check("severity = high for HOOK_JMP", res and res[0]["severity"] == "high", res)

live = bytearray(base)
live[0x20] = 0xC3                                # early-ret at a function start
res = P.diff_blocks(bytes(base), bytes(live))
check("0xC3 write classified EARLY_RET", res and res[0]["kind"] == "EARLY_RET", res)

live = bytearray(base)
for i in range(0, len(live), 8):
    live[i] = 0x00
res = P.diff_blocks(bytes(base), bytes(live))
check("widespread patching reported block-by-block", len(res) == len(base) // P.BLOCK + (1 if len(base) % P.BLOCK else 0), len(res))

res = P.diff_blocks(bytes(base), bytes(base[:60]))
check("size change reported as SIZE_MISMATCH", any(r["kind"] == "SIZE_MISMATCH" for r in res), res)

# base_rva offsetting (module-relative reporting)
patched = bytearray(base)
patched[0] = 0xE9
res = P.diff_blocks(bytes(base), bytes(patched), base_rva=0x1000)
check("base_rva shifts the reported RVA", res and res[0]["rva"] == "0x1000", res)

# PE header parsing
img = fake_pe(text_rva=0x2000, text_size=0x200)
rng = P.section_range_from_headers(img, ".text")
check("parses .text (rva,size) from an in-memory image header", rng == (0x2000, 0x200), rng)
check("missing section returns None", P.section_range_from_headers(img, ".rdata") is None)
check("garbage input returns None (fail safe)", P.section_range_from_headers(b"not a pe" * 8, ".text") is None)

# read-only-by-construction guardrail: no process-mutation API may be *called*.
# Parsed from the AST (identifiers only) so prose in docstrings/comments cannot
# create false passes or false failures.
import ast
tree = ast.parse(open(os.path.join(HERE, "nrth_probe.py"), "r", encoding="utf-8").read())
idents = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Attribute) or isinstance(node, ast.Name):
        idents.add(node.attr.lower() if isinstance(node, ast.Attribute) else node.id.lower())
for forbidden in ("writeprocessmemory", "virtualprotectex", "createremotethread",
                  "virtualallocex", "queueuserapcall", "setwindowshookexa",
                  "flushinstructioncache", "ntunmapviewofsection"):
    check("AST: no %s call site in the probe" % forbidden, forbidden not in idents, sorted(idents)[:5])
check("AST: OpenProcess is the only process handle API", "openprocess" in idents and "openprocessex" not in idents)
check("AST: ReadProcessMemory present (read path)", "readprocessmemory" in idents)

# offline CLI end-to-end (diff mode) — real subprocess, real exit codes
tmp = "/tmp/nrth_probe_test"
os.makedirs(tmp, exist_ok=True)
a, b = os.path.join(tmp, "a.bin"), os.path.join(tmp, "b.bin")
ba = bytearray(b"\x55\x8b\xec" * 200)
bb = bytearray(ba)
bb[0x100] = 0xC3
open(a, "wb").write(bytes(ba))
open(b, "wb").write(bytes(bb))
proc = subprocess.run([sys.executable, os.path.join(HERE, "nrth_probe.py"), "diff", a, b],
                      capture_output=True, text=True)
out = json.loads(proc.stdout)
check("CLI diff exits 1 when code differs", proc.returncode == 1, proc.returncode)
check("CLI diff reports the EARLY_RET block", out["changed_blocks"] == 1 and out["anomalies"][0]["kind"] == "EARLY_RET", out)
proc2 = subprocess.run([sys.executable, os.path.join(HERE, "nrth_probe.py"), "diff", a, a],
                        capture_output=True, text=True)
check("CLI diff exits 0 on identical input", proc2.returncode == 0, proc2.stdout[-200:])
proc3 = subprocess.run([sys.executable, os.path.join(HERE, "nrth_probe.py"), "check", "--pid", "1", "--baseline", "/nonexistent"],
                       capture_output=True, text=True)
check("live modes fail safe off-Windows (no silent pass)", proc3.returncode != 0, proc3.returncode)

print("== result: %d passed, %d failed ==" % (PASS, len(FAIL)))
sys.exit(1 if FAIL else 0)
