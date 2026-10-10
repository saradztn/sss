#!/usr/bin/env python3
"""nrth_hook_targets.py — map every obfuscated byte-signature in NRTH.dll to the
module it is scanned in and to what the sample then does with the match.

Read-only. For each recovered pattern record (tools/nrth_strings_recover.py) we find
the enclosing function, then look inside that function for:
  * the module-name record used next to it  (client.dll / netc.dll / d3d9.dll / ...)
  * the resolver call  0x10002960           (module + wildcard pattern scan)
  * MinHook calls      0x100363f0 / 0x100362c0 / 0x10036020 (MH_Initialize/Enable/
                       MH_CreateHook) — and the detour address passed in edx
  * a `mov byte ptr [...], 0C3h` store     — the RET "kill switch" write
so defenders learn the full hook surface, not only the two Lua-VM hooks.

Usage: python3 nrth_hook_targets.py <NRTH.dll>
"""
import struct
import sys
import collections

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from nrth_strings_recover import Image, recover, func_bounds  # noqa: E402

RESOLVER = 0x10002960
MH_CREATE = 0x10036020
MH_ENABLE = 0x100363f0
MH_DISABLE = 0x100362c0
MODULES = ("client.dll", "netc.dll", "d3d9.dll", "lua5.1.dll")


def main(path):
    img = Image(path)
    pe = img.pe
    base = pe.OPTIONAL_HEADER.ImageBase
    code = img.code()
    va0 = img.va0()
    ins = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, va0))
    by_va = {i.address: i for i in ins}

    decs, records = recover(img)
    pats = [r for r in records if r["text"].startswith("55 8B ")]
    print("[*] %d pattern records recovered from %d obfuscated records" % (len(pats), len(records)))

    rows = []
    for r in sorted({p["text"]: p for p in pats}.values(), key=lambda x: x["site"]):
        site = r["site"]
        f0, f1 = func_bounds(ins, site)
        mods, hooks, kills, resolver = collections.OrderedDict(), [], [], 0
        detours = []
        for m in ins:
            if f0 is None or not (f0 <= m.address < f1):
                continue
            if m.mnemonic == "call":
                try:
                    t = int(m.op_str, 16)
                except ValueError:
                    continue
                if t == RESOLVER:
                    resolver += 1
                elif t == MH_CREATE:
                    hooks.append(m.address)
                elif t in (MH_ENABLE, MH_DISABLE):
                    pass
            # mov byte ptr [reg+disp], 0C3   -> c6 41/42/46/48/79/7B .. c3  (or [abs])
            if m.mnemonic == "mov" and m.op_str.endswith("0xc3") and "byte ptr" in m.op_str:
                kills.append(m.address)
            if m.mnemonic == "mov" and m.op_str.startswith("edx, 0x10"):
                detours.append((m.address, int(m.op_str.split("0x")[1], 16)))
            if m.mnemonic == "call" and m.bytes[0] == 0xFF:
                pass
        # module context: which module-name records are built in the same function
        found_mods = []
        for q in records:
            if q["text"] in MODULES and f0 and f0 <= q["site"] < f1:
                found_mods.append(q["text"])
        rows.append(dict(pattern=r["text"], site=site, func=f0, resolver=resolver,
                         mh=len(hooks), kills=len(kills),
                         mods=sorted(set(found_mods)) or ["(not resolved)"],
                         detours=sorted(set(d[1] for d in detours))))

    for n, x in enumerate(rows, 1):
        print("\n[%02d] pattern : %s" % (n, x["pattern"]))
        print("     record site   : 0x%08x   enclosing func: %s"
              % (x["site"], ("0x%08x" % x["func"]) if x["func"] else "unknown"))
        print("     module scan   : %s" % ", ".join(x["mods"]))
        print("     pattern scans : %d   MH_CreateHook: %d   byte=0xC3 writes: %d"
              % (x["resolver"], x["mh"], x["kills"]))
        if x["detours"]:
            print("     detour addrs  : %s" % ", ".join("0x%08x" % d for d in x["detours"]))
    print("\n[*] %d distinct hook-target signatures mapped" % len(rows))
    return rows


if __name__ == "__main__":
    main(sys.argv[1])
