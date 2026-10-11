#!/usr/bin/env python3
"""nrth_netc_fixture.py — positive control for the tamper path: a fixture image that carries the
exact byte footprint the sample writes, so the detector's ALERT side can be tested end to end.

Why a fixture instead of the real code path
-------------------------------------------
The sample's `netc.dll` cluster works like this (all Observed in `mta_blue_team_case/`): the
scan/patch routine at 0x10020640 resolves integrity-check functions by pattern and kills them with
the writer at 0x10011870 (`VirtualProtect(ptr,1,0x40,&old)` + a 1-byte copy of `0xC3`); it hooks 4
others with MinHook near jumps. Writing that against a running client is anti-cheat tampering,
which this case's scope line excludes. A detector does not need the attack, it needs a *known-true
image to fire on* — that is this tool. The fixture's functions carry exactly the pattern bytes from
the compiled signature table (`src/nrth_audit_sigs.h` is parsed, never re-typed, so the fixture
cannot drift from the detector) and the patched variant carries exactly the bytes the sample writes.
Expectations are therefore arithmetic, not opinion: `kills` KILL_RET + `detours` DETOUR_JMP32.

Usage
-----
  nrth_netc_fixture.py [--sigs-header src/nrth_audit_sigs.h] [--out-dir ../working]
                       [--kills 6] [--detours 4] [--print-sizes]
Writes <out>/fixture_netc_pristine.dll, <out>/fixture_netc_killed.dll, <out>/fixture_netc.json and
prints the manifest. Exit 0 on success, 2 on a parse problem.
"""
import argparse
import json
import os
import re
import struct
import sys

FILL = 0x22                                     # byte written into every '?' of a pattern; never a
                                                # footprint prefix, so it cannot fake a second hit
BLOCK = 0x40                                    # bytes between two fixture functions
KILL = bytes.fromhex('c3')                      # the sample's 1-byte kill  (kNvxaFootprint[0])
DETOUR = bytes.fromhex('e9 22 22 22 22')        # MinHook near jmp          (kNvxaFootprint[1])
ROW = re.compile(r'\{\s*(\d+),\s*"([0-9A-Fa-f? ]{8,})"\s*,\s*"([^"]*)"', re.S)

IMAGE_BASE = 0x10000000
TEXT_RVA = 0x1000
FILE_ALIGN = 0x200
SEC_ALIGN = 0x1000
HDR = 0x200


def table_rows(path):
    """(id, pattern, target) for every compiled signature row."""
    txt = open(path, encoding='utf-8', errors='replace').read()
    return [(int(i), p.strip(), t) for i, p, t in ROW.findall(txt)]


def pat_bytes(pattern, cap):
    """Concrete bytes for an anchor pattern: literal tokens as-is, each '?' as FILL."""
    out = bytearray()
    for tok in pattern.split():
        if len(out) >= cap:
            break
        out.append(FILL if tok == '?' else int(tok, 16))
    return bytes(out)


def build_image(text_bytes):
    """Minimal but structurally real PE32 (i386, one .text, no data directories): the same header
    choices the sample uses where they are independent of content — ImageBase 0x10000000,
    Subsystem 3, DllCharacteristics DYNAMICBASE|NX_COMPAT, checksum 0, 512-byte alignments."""
    pad = (-len(text_bytes)) % FILE_ALIGN
    body = text_bytes + b'\0' * pad
    size_of_image = TEXT_RVA + len(body)

    dos = bytearray(0x80)                     # DOS stub ends where the NT headers begin
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 0x80)    # e_lfanew -> 'PE\0\0' at 0x80

    coff = struct.pack('<HHIIIHH', 0x14C, 1, 0, 0, 0, 0xE0, 0x2102)
    opt = bytearray(0xE0)
    struct.pack_into('<HBB', opt, 0, 0x10B, 14, 0)                 # magic, linker 14.0
    struct.pack_into('<I', opt, 4, len(body))                      # SizeOfCode
    struct.pack_into('<I', opt, 16, 0)                             # AddressOfEntryPoint
    struct.pack_into('<I', opt, 28, IMAGE_BASE)
    struct.pack_into('<I', opt, 32, SEC_ALIGN)
    struct.pack_into('<I', opt, 36, FILE_ALIGN)
    struct.pack_into('<HH', opt, 40, 4, 0)                         # OS 4.0
    struct.pack_into('<II', opt, 52, size_of_image, HDR)
    struct.pack_into('<I', opt, 60, 0)                             # checksum 0 (like the sample)
    struct.pack_into('<H', opt, 68, 3)                             # subsystem CUI (like the sample)
    struct.pack_into('<H', opt, 70, 0x0140)                         # DYNAMICBASE | NX_COMPAT
    for o, v in ((72, 0x100000), (76, 0x1000), (80, 0x100000), (84, 0x1000)):
        struct.pack_into('<I', opt, o, v)
    struct.pack_into('<I', opt, 92, 16)                             # NumberOfRvaAndSizes

    sh = bytearray(40)
    sh[0:8] = b'.text\0\0\0'
    struct.pack_into('<IIII', sh, 8, len(body), TEXT_RVA, len(body), HDR)   # vsize, va, rawsize, rawptr
    struct.pack_into('<I', sh, 36, 0x60000020)                      # CODE|EXECUTE|READ

    head = bytes(dos) + b'PE\0\0' + coff + bytes(opt) + bytes(sh)
    assert len(head) <= HDR, f"headers do not fit in {HDR:#x} bytes (got {len(head):#x})"
    head += b'\0' * (HDR - len(head))          # section raw data starts at HDR
    return head + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--sigs-header', default='src/nrth_audit_sigs.h')
    ap.add_argument('--out-dir', default='../working')
    ap.add_argument('--kills', type=int, default=6)
    ap.add_argument('--detours', type=int, default=4)
    ap.add_argument('--prefer-target', default='netc.dll',
                    help="rows whose target equals this are the ones killed first (default netc.dll)")
    ap.add_argument('--print-sizes', action='store_true')
    ns = ap.parse_args()

    rows = table_rows(ns.sigs_header)
    if not rows:
        print(f"[!] no signature rows found in {ns.sigs_header}")
        return 2
    n = len(rows)
    kills = max(0, min(ns.kills, n))
    detours = max(0, min(ns.detours, n - kills))

    order = sorted(range(n), key=lambda i: (rows[i][2] != ns.prefer_target, i))
    hit = {order[j]: ('KILL_RET' if j < kills else 'DETOUR_JMP32') for j in range(kills + detours)}
    clean, patched, manifest = bytearray(), bytearray(), []
    for idx, (sid, pat, target) in enumerate(rows):
        body = pat_bytes(pat, BLOCK)
        clean += body + b'\0' * (BLOCK - len(body))
        pbody = bytearray(body)
        state = hit.get(idx, 'pristine')
        if state == 'KILL_RET':
            pbody = bytearray(KILL + bytes(body[len(KILL):]))
        elif state == 'DETOUR_JMP32':
            pbody = bytearray(DETOUR + bytes(body[len(DETOUR):]))
        patched += bytes(pbody) + b'\0' * (BLOCK - len(pbody))
        manifest.append({'sig_id': sid, 'target': target, 'state': state,
                         'rva': TEXT_RVA + idx * BLOCK, 'pattern_len': len(body)})

    os.makedirs(ns.out_dir, exist_ok=True)
    pri_img, kil_img = build_image(bytes(clean)), build_image(bytes(patched))
    p_pri = os.path.join(ns.out_dir, 'fixture_netc_pristine.dll')
    p_kil = os.path.join(ns.out_dir, 'fixture_netc_killed.dll')
    open(p_pri, 'wb').write(pri_img)
    open(p_kil, 'wb').write(kil_img)
    doc = {'source': os.path.basename(ns.sigs_header), 'image_base': IMAGE_BASE,
           'signatures': n, 'kills': kills, 'detours': detours,
           'pristine_bytes': len(pri_img), 'killed_bytes': len(kil_img),
           'expect': {'audit_pristine_patched': 0, 'audit_killed_patched': kills + detours,
                      'diff_added_footprint': kills + detours, 'diff_target_lost': 0},
           'rows': manifest}
    with open(os.path.join(ns.out_dir, 'fixture_netc.json'), 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=1)
    print(f"[+] {n} fixture functions, one per compiled signature "
          f"({len(pri_img)} bytes per image, .text rva 0x{TEXT_RVA:x}, {BLOCK:#x} apart)")
    print(f"[*] footprint applied: {kills} x C3 (the writer at 0x10011870) + {detours} x E9 jmp "
          f"-> expected detector alert count {kills + detours}")
    for m in manifest:
        if m['state'] != 'pristine':
            print(f"    sig[{m['sig_id']:2}] {m['target']:11} {m['state']:13} rva 0x{m['rva']:08x}")
    if ns.print_sizes:
        print(f"[+] wrote {p_pri} ({len(pri_img)}) and {p_kil} ({len(kil_img)})")
    return 0


if __name__ == '__main__':
    sys.exit(main())
