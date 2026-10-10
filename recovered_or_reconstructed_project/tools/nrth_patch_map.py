#!/usr/bin/env python3
"""Enumerate the sample's one-byte "kill switch" patches: writer call site -> the
pattern record and module used to locate the target. Read-only analysis."""
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

sys.path.insert(0, "recovered_or_reconstructed_project/tools")
from nrth_strings_recover import Image, recover  # noqa: E402

WRITER = 0x10011870
RESOLVER = 0x10002960
HEXISH = set("0123456789ABCDEF ")

img = Image(sys.argv[1] if len(sys.argv) > 1 else "working/NRTH.dll")
base = img.pe.OPTIONAL_HEADER.ImageBase
code, va0 = img.code(), img.va0()
ins = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, va0))
_decs, records = recover(img)
rec_sites = sorted((r["site"], r["text"]) for r in records)

writer_calls = [m.address for m in ins if m.mnemonic == "call" and m.op_str == "0x%x" % WRITER]
print("[*] sample            : %s (imagebase 0x%08x)" % (sys.argv[1], base))
print("[*] byte writer       : VA 0x%08X  (VirtualProtect RW -> store byte -> restore)" % WRITER)
print("[*] writer call sites : %s" % ", ".join("0x%08x" % a for a in writer_calls))

for wc in writer_calls:
    val = None
    for m in reversed([x for x in ins if x.address < wc][-60:]):
        if m.mnemonic == "mov" and "byte ptr" in m.op_str and m.op_str.rstrip().endswith("0xc3"):
            val = 0xC3
            break
    res = [m.address for m in ins
           if m.address < wc and m.mnemonic == "call" and m.op_str == "0x%x" % RESOLVER]
    rcall = res[-1] if res else None
    pat, mod = None, None
    for site, text in rec_sites:
        if rcall and site < rcall:
            if all(c in HEXISH for c in text) and len(text) > 12 and "?" in text:
                pat = (site, text)
            if text.endswith(".dll"):
                mod = text
    print("\n  patch site 0x%08x" % wc)
    print("    byte written  : %s" % ("0x%02X (RET -> function returns immediately)" % val if val else "non-immediate"))
    print("    locator call  : %s (pattern scan helper)" % ("0x%08x" % rcall if rcall else "not found"))
    print("    target module : %s" % (mod or "?"))
    print("    pattern       : %s" % (repr(pat[1]) if pat else "?"))
print("\n[*] %d patch sites total" % len(writer_calls))
