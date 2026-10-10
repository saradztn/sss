#!/usr/bin/env python3
"""pe_summary.py — dependency-free PE header/section/export summary.

Written for this case because the audit tool must be verifiable on a machine that has
nothing installed but Python: "is this the PE32/x86 image we think we built, and does it
export the names our rules/CLI expect?" is a question you can answer without pefile,
dumpbin or objdump.

It parses exactly what it prints (DOS header -> PE signature -> COFF header -> optional
header magic -> section table -> export directory RVAs). Anything it does not understand
is reported as such instead of guessed.

    python3 tools/pe_summary.py bin/NRTH_audit.dll [more.exe ...]

Exit status: 0 if every file parsed as PE32/PE32+, 1 otherwise.
"""
import struct
import sys

MACHINE = {0x014C: "IMAGE_FILE_MACHINE_I386 (x86)",
           0x8664: "IMAGE_FILE_MACHINE_AMD64 (x64)",
           0x01C0: "ARM", 0xAA64: "ARM64"}
SUBSYS = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI (console)", 9: "CE"}
DCHAR = [(0x0020, "HIGH_ENTROPY_VA"), (0x0040, "DYNAMICBASE"), (0x0100, "NX_COMPAT"),
         (0x0200, "NO_ISOLATION"), (0x0400, "NO_SEH"), (0x0800, "NO_BIND"),
         (0x2000, "GUARD_CF"), (0x0080, "TERMINAL_SERVER_AWARE")]


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def rva_to_off(sections, rva):
    for s in sections:
        if s[1] <= rva < s[1] + max(s[2], s[3]):
            return s[4] + (rva - s[1])
    return None


def summarize(path):
    data = open(path, "rb").read()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not an MZ image")
    pe = u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("no PE signature at 0x%x" % pe)
    nsec = u16(data, pe + 6)
    ts = u32(data, pe + 8)
    optsize = u16(data, pe + 20)
    chars = u16(data, pe + 22)
    machine = u16(data, pe + 4)
    opt = pe + 24
    magic = u16(data, opt)
    if magic == 0x10B:
        imagebase, entry, sizeimg = u32(data, opt + 28), u32(data, opt + 16), u32(data, opt + 56)
        dchar = u16(data, opt + 70)
        nvsec = 16
        dirs = opt + 96
    elif magic == 0x20B:
        imagebase, entry, sizeimg = u32(data, opt + 24), u32(data, opt + 16), u32(data, opt + 56)
        dchar = u16(data, opt + 70)
        nvsec = 16
        dirs = opt + 112
    else:
        raise ValueError("unknown optional header magic 0x%x" % magic)

    sec = []
    stab = opt + optsize
    for i in range(nsec):
        e = stab + i * 40
        name = data[e:e + 8].rstrip(b"\0").decode("latin-1")
        sec.append((name, u32(data, e + 12), u32(data, e + 8), u32(data, e + 16), u32(data, e + 20)))

    print("%s" % path)
    print("  size            : %d bytes" % len(data))
    print("  timestamp       : 0x%08x" % ts)
    print("  machine         : 0x%04x  %s" % (machine, MACHINE.get(machine, "?")))
    print("  magic           : 0x%03x (%s)" % (magic, "PE32" if magic == 0x10B else "PE32+"))
    print("  image base      : 0x%08x" % imagebase)
    print("  entry point RVA : 0x%08x" % entry)
    print("  size of image   : 0x%x" % sizeimg)
    print("  subsystem       : %s" % SUBSYS.get(u16(data, opt + 68), "?"))
    print("  DLL flags       : 0x%04x  %s" % (dchar, " ".join(v for k, v in DCHAR if dchar & k)))
    print("  file chars      : 0x%04x%s" % (chars, "  [EXECUTABLE_IMAGE]" if chars & 0x0002 else ""))
    print("  sections        :")
    for name, rva, vsz, rsz, raw in sec:
        print("      %-8s rva=0x%07x vsize=0x%06x raw=0x%06x rsize=0x%06x" % (name, rva, vsz, raw, rsz))

    exp_rva = u32(data, dirs)
    if not exp_rva:
        print("  exports         : (none)")
        return
    eo = rva_to_off(sec, exp_rva)
    if eo is None:
        print("  exports         : directory at rva 0x%x not covered by any section" % exp_rva)
        return
    # IMAGE_EXPORT_DIRECTORY: Name@12 OrdinalBase@16 NumberOfFunctions@20 NumberOfNames@24
    #                    AddressOfFunctions@28 AddressOfNames@32 AddressOfNameOrdinals@36
    nnames = u32(data, eo + 24)
    nfuncs = u32(data, eo + 20)
    ord_base = u32(data, eo + 16)
    dll_name = ""
    if u32(data, eo + 12):
        no = rva_to_off(sec, u32(data, eo + 12))
        dll_name = data[no:data.index(b"\0", no)].decode("latin-1") if no else ""
    addr_names = rva_to_off(sec, u32(data, eo + 32))
    addr_ords = rva_to_off(sec, u32(data, eo + 36))
    addr_funcs = rva_to_off(sec, u32(data, eo + 28))
    rows = []
    for i in range(nnames):
        nro = rva_to_off(sec, u32(data, addr_names + i * 4))
        if nro is None:
            continue
        nm = data[nro:data.index(b"\0", nro)].decode("latin-1")
        idx = u16(data, addr_ords + i * 2) if addr_ords else 0
        ordinal = ord_base + idx
        rva = u32(data, addr_funcs + idx * 4) if addr_funcs else 0
        rows.append((ordinal, nm, rva))
    print("  exports         : %d name(s) / %d function(s)%s" % (
        len(rows), nfuncs, ("  internal name " + dll_name) if dll_name else ""))
    for ordinal, nm, rva in sorted(rows):
        print("      @%-3d %-28s rva=0x%06x" % (ordinal, nm, rva))


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    bad = 0
    for p in argv[1:]:
        try:
            summarize(p)
        except Exception as exc:                                   # noqa: BLE001
            print("%s: cannot parse (%s)" % (p, exc))
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
