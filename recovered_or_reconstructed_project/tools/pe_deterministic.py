#!/usr/bin/env python3
"""pe_deterministic.py — make a PE artifact hash-pinnable by removing per-link entropy.

Why this exists: the case docs kept having to say "the SHA-256 changes on every rebuild, so compare
sizes and exports instead". That is a property of *two specific linker outputs*, not of PE: zig's lld
ignores --no-insert-timestamp / --timestamp, and it writes a fresh CodeView PDB GUID on every link.
Measured on NRTH_audit.dll (292,864 B, two links of the SAME object file, 2 s apart): 12 differing
bytes -

    0x000080  TimeDateStamp (COFF file header)
    0x0041f39 the module's own name in the export dir  (only differs if -o differs)
    0x0042604 .buildid payload
    0x0042620.. debug directory + IMAGE_DEBUG_TYPE_CODEVIEW record (RSDS GUID + age)

This tool zeroes the first, third and fourth. It is pure file surgery: it never recomputes anything
the loader needs (CheckSum is unused by the Windows loader and already 0 here), it does not touch
relocations, and it is idempotent. Debug/PDB linkage is intentionally destroyed - these are release
artifacts whose debug info is a stray .pdb that zig emits regardless of -g0 and that nobody ships.

Usage
  pe_deterministic.py <pe> [<pe> ...]        normalise in place, print old -> new sha256
  pe_deterministic.py --check <pe> [...]     report what entropy is present, change nothing

After normalising, `sha256sum` is a usable pin for review/allow-listing: rebuilding the same sources
with the same toolchain reproduces the same hash (verified in BUILD_LOG.txt, 2026-10-11).
"""
import argparse
import hashlib
import struct
import sys

DEBUG_DIR_INDEX = 6          # IMAGE_DIRECTORY_ENTRY_DEBUG
CODEVIEW_TYPE = 2            # IMAGE_DEBUG_TYPE_CODEVIEW


def parse(d):
    e = struct.unpack_from('<I', d, 0x3c)[0]
    if d[e:e + 4] != b'PE\0\0':
        raise ValueError("not a PE image")
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsize = struct.unpack_from('<H', d, e + 20)[0]
    opt = e + 24
    magic = struct.unpack_from('<H', d, opt)[0]
    if magic not in (0x10b, 0x20b):
        raise ValueError(f"unexpected optional header magic 0x{magic:x}")
    dd = opt + (96 if magic == 0x10b else 112)
    secs = opt + optsize
    sections = []
    for i in range(nsec):
        o = secs + i * 40
        name = d[o:o + 8].rstrip(b'\0').decode('latin1')
        vsz, va, rsz, ro = struct.unpack_from('<IIII', d, o + 8)
        sections.append({'name': name, 'va': va, 'vsz': vsz, 'ro': ro, 'rsz': rsz, 'hdr': o})
    return {'e': e, 'opt': opt, 'dd': dd, 'sections': sections, 'magic': magic}


def rva_to_off(h, rva):
    for s in h['sections']:
        if s['va'] <= rva < s['va'] + max(s['vsz'], s['rsz']) and s['rsz']:
            o = s['ro'] + (rva - s['va'])
            if o < s['ro'] + s['rsz']:
                return o
    return None


def normalise(path, check_only=False):
    try:
        raw = open(path, 'rb').read()
    except OSError as ex:
        print(f"[!] {path}: {ex}")
        return 1
    try:
        h = parse(raw)
    except ValueError as ex:
        print(f"[!] {path}: {ex}")
        return 1
    d = bytearray(raw)
    e, opt, dd = h['e'], h['opt'], h['dd']
    actions = []

    ts = struct.unpack_from('<I', d, e + 8)[0]
    if ts:
        actions.append(f"TimeDateStamp 0x{ts:08x} -> 0")
        if not check_only:
            struct.pack_into('<I', d, e + 8, 0)

    # debug directory: zero the entry (20 B) and the CodeView record it points at, then clear
    # the data-directory entry so no loader/tool follows the emptied record.
    dbg_rva, dbg_sz = struct.unpack_from('<II', d, dd + 8 * DEBUG_DIR_INDEX)
    if dbg_rva:
        off = rva_to_off(h, dbg_rva)
        if off is not None:
            # IMAGE_DEBUG_DIRECTORY: chars, ts, major/minor, type, sizeOfData, rva, rawPtr
            dtype, dsz, drva, dptr = struct.unpack_from('<IIII', d, off + 12)
            n = max(int(dbg_sz), 20)
            note = f"type {dtype}"
            if dtype == CODEVIEW_TYPE and dptr and dptr + dsz <= len(d):
                # the record itself (RSDS + PDB GUID + age + filename) is the real entropy
                span = range(dptr, min(len(d), dptr + dsz))
                if not any(s['ro'] <= a < s['ro'] + s['rsz'] and s['name'] == '.buildid'
                           for s in h['sections'] for a in span[:1]):
                    actions.append(f"CodeView record at 0x{dptr:x} ({dsz} B) -> zeroed")
                    if not check_only:
                        for a in span:
                            d[a] = 0
            actions.append(f"debug directory at rva 0x{dbg_rva:x} ({n} B, {note}) -> zeroed, entry cleared")
            if not check_only:
                for i in range(n):
                    if off + i + 4 <= len(d):
                        d[off + i] = 0
                struct.pack_into('<II', d, dd + 8 * DEBUG_DIR_INDEX, 0, 0)
        else:
            actions.append(f"debug dir rva 0x{dbg_rva:x} not mapped (left alone)")

    # .buildid: the linker's build id (and, with lld, the tail that carries the PDB GUID)
    for s in h['sections']:
        if s['name'] in ('.buildid', '.note.GNU-buildid') and s['rsz']:
            nz = sum(1 for c in raw[s['ro']:s['ro'] + s['rsz']] if c)
            if nz:
                actions.append(f".buildid ({s['rsz']} B, {nz} non-zero) -> zeroed")
                if not check_only:
                    for i in range(s['ro'], min(len(d), s['ro'] + s['rsz'])):
                        d[i] = 0

    # COFF symbol table pointer, if it lives outside the sections (lld puts /4 in a section here,
    # which is deterministic, so only the trailing pointer form is neutralised)
    pst, nsym = struct.unpack_from('<II', d, e + 16)
    if nsym and pst >= len(raw) - 4:
        actions.append(f"symbol table at end of file ({nsym} syms @0x{pst:x}) -> pointer dropped")
        if not check_only:
            struct.pack_into('<II', d, e + 16, 0, 0)

    old = hashlib.sha256(raw).hexdigest()
    if check_only:
        print(f"[*] {path}: {len(actions)} entropy source(s)")
        for a in actions:
            print(f"      - {a}")
        if not actions:
            print("      (none: already deterministic)")
        return 0 if not actions else 1
    if not actions:
        print(f"[=] {path}: already deterministic  sha256 {old[:16]}…")
        return 0
    open(path, 'wb').write(bytes(d))
    new = hashlib.sha256(bytes(d)).hexdigest()
    print(f"[+] {path}: {len(actions)} entropy source(s) removed")
    for a in actions:
        print(f"      - {a}")
    print(f"    sha256 {old} -> {new}")
    return 0


def main():
    ap = argparse.ArgumentParser(add_help=True, description=__doc__.split('\n')[0])
    ap.add_argument('files', nargs='+')
    ap.add_argument('--check', action='store_true', help="report entropy, change nothing")
    ns = ap.parse_args()
    rc = 0
    for f in ns.files:
        rc |= normalise(f, ns.check)
    return rc


if __name__ == '__main__':
    sys.exit(main())
