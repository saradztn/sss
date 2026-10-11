#!/usr/bin/env python3
"""nrth_parity.py — how close is the reconstruction to the original, field by field.

Two independent axes, both measured from files rather than asserted in prose:

  A. PE STRUCTURE ("formal"): every file-header, optional-header, data-directory and section-table
     field of the original vs the rebuild, tagged with whether the difference is *fixable* by build
     flags, *toolchain-bound* (MSVC vs clang/lld emit different sections, debug directories, symbol
     tables and linker versions that no flag can fake without lying), or *cosmetic*.

  B. BEHAVIOUR COVERAGE ("functional"): every mapped function in function_map.csv for the module is
     looked up in the reconstruction's sources. A label found as an identifier means the step is
     implemented; a VA found only inside a comment means it is documented but deliberately not
     implemented (the case's scope line); neither means it is not covered at all.

Usage:
  nrth_parity.py <original.dll> <rebuilt.dll> [--map ../mta_blue_team_case/function_map.csv]
                 [--src src] [--out report.md] [--json]

Exit code is always 0 (this is a report, not a gate) unless a file cannot be read.
"""
import argparse
import json
import os
import re
import struct
import sys

DIR_NAMES = [
    "export", "import", "resource", "exception", "certificate", "base_reloc", "debug", "arch",
    "global_ptr", "tls", "load_config", "bound_import", "iat", "delay_import",
    "clr_runtime_header", "reserved",
]
# fields whose value a build flag can align, given the same content
FIXABLE = {
    'image_base', 'section_alignment', 'file_alignment', 'subsystem', 'size_of_image',
    'dll_characteristics', 'size_of_headers', 'checksum', 'address_of_entry_point',
}
# fields that identify the compiler/linker itself: matching them means forging, not reconstructing
TOOLCHAIN = {
    'linker_version', 'os_version', 'image_version', 'subsystem_version', 'sections',
    'data_directories', 'number_of_sections', 'size_of_stack_reserve', 'size_of_stack_commit',
    'size_of_heap_reserve', 'size_of_heap_commit',
}


class PE:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        self.path = path
        d = self.d
        self.pe = struct.unpack_from('<I', d, 0x3c)[0]
        if d[self.pe:self.pe + 4] != b'PE\0\0':
            raise ValueError(f"{path}: not a PE image")
        (self.machine, self.nsec, self.ts, self.ptr_sym, self.nsym,
         self.optsize, self.chars) = struct.unpack_from('<HHIIIHH', d, self.pe + 4)
        self.opt = self.pe + 24
        self.magic = struct.unpack_from('<H', d, self.opt)[0]
        pe32 = self.magic == 0x10b
        self.linker_version = "%d.%d" % (d[self.opt + 2], d[self.opt + 3])
        self.size_of_image = struct.unpack_from('<I', d, self.opt + 56)[0]
        self.base_of_code = struct.unpack_from('<I', d, self.opt + 40)[0]
        self.entry = struct.unpack_from('<I', d, self.opt + 16)[0]
        self.image_base = struct.unpack_from('<I', d, self.opt + 28)[0]
        self.sec_align = struct.unpack_from('<I', d, self.opt + 32)[0]
        self.file_align = struct.unpack_from('<I', d, self.opt + 36)[0]
        self.os_version = "%d.%d" % (d[self.opt + 40 + (0 if pe32 else -4)], d[self.opt + 42])
        self.subsystem = struct.unpack_from('<H', d, self.opt + (68 if pe32 else 68))[0]
        self.dll_chars = struct.unpack_from('<H', d, self.opt + (70 if pe32 else 70))[0]
        self.stack_res = struct.unpack_from('<I', d, self.opt + (72 if pe32 else 88))[0]
        self.stack_com = struct.unpack_from('<I', d, self.opt + (76 if pe32 else 92))[0]
        self.heap_res = struct.unpack_from('<I', d, self.opt + (80 if pe32 else 96))[0]
        self.heap_com = struct.unpack_from('<I', d, self.opt + (84 if pe32 else 100))[0]
        self.checksum = struct.unpack_from('<I', d, self.opt + 64)[0]
        self.size_of_headers = struct.unpack_from('<I', d, self.opt + 60)[0]
        dd = self.opt + (96 if pe32 else 112)
        self.ndir = struct.unpack_from('<I', d, self.opt + (92 if pe32 else 108))[0]
        self.dirs = [struct.unpack_from('<II', d, dd + 8 * i) for i in range(min(self.ndir, 16))]
        self.sections = []
        so = self.opt + self.optsize
        for i in range(self.nsec):
            o = so + i * 40
            name = d[o:o + 8].rstrip(b'\0').decode('latin1') or d[o:o + 8].split(b'\0')[0].decode('latin1')
            vsz, va, rsz, ro = struct.unpack_from('<IIII', d, o + 8)
            schars = struct.unpack_from('<I', d, o + 36)[0]
            self.sections.append((name, va, vsz, ro, rsz, schars))

    def section_of_rva(self, r):
        for name, va, vsz, ro, rsz, _ in self.sections:
            if va <= r < va + max(vsz, rsz):
                return name, ro + (r - va)
        return None, None

    def field(self, key):
        return getattr(self, key, None)


def structure_report(a, b):
    rows = []
    fields = [
        ('number_of_sections', 'sections', a.nsec, b.nsec),
        ('machine', 'machine', hex(a.machine), hex(b.machine)),
        ('magic', 'pe32/32+', hex(a.magic), hex(b.magic)),
        ('linker_version', 'linker version', a.linker_version, b.linker_version),
        ('image_base', 'image base', '0x%x' % a.image_base, '0x%x' % b.image_base),
        ('address_of_entry_point', 'entry RVA', '0x%x' % a.entry, '0x%x' % b.entry),
        ('size_of_image', 'size of image', '0x%x' % a.size_of_image, '0x%x' % b.size_of_image),
        ('size_of_headers', 'size of headers', '0x%x' % a.size_of_headers, '0x%x' % b.size_of_headers),
        ('section_alignment', 'section align', hex(a.sec_align), hex(b.sec_align)),
        ('file_alignment', 'file align', hex(a.file_align), hex(b.file_align)),
        ('os_version', 'OS version', a.os_version, b.os_version),
        ('subsystem', 'subsystem', str(a.subsystem), str(b.subsystem)),
        ('dll_characteristics', 'DllCharacteristics', '0x%04x' % a.dll_chars, '0x%04x' % b.dll_chars),
        ('size_of_stack_reserve', 'stack reserve', hex(a.stack_res), hex(b.stack_res)),
        ('size_of_stack_commit', 'stack commit', hex(a.stack_com), hex(b.stack_com)),
        ('size_of_heap_reserve', 'heap reserve', hex(a.heap_res), hex(b.heap_res)),
        ('size_of_heap_commit', 'heap commit', hex(a.heap_com), hex(b.heap_com)),
        ('checksum', 'checksum', hex(a.checksum), hex(b.checksum)),
        ('chars', 'file characteristics', '0x%04x' % a.chars, '0x%04x' % b.chars),
    ]
    for key, label, va, vb in fields:
        rows.append({'axis': 'structure', 'item': label, 'original': va, 'rebuilt': vb,
                     'match': va == vb, 'kind': ('fixable' if key in FIXABLE else
                                                 'toolchain-bound' if key in TOOLCHAIN else 'other')})
    # data directories: presence pattern is the interesting part (debug/load-config/tls/bound)
    pa = [(DIR_NAMES[i], a.dirs[i][0], a.dirs[i][1]) for i in range(len(a.dirs)) if a.dirs[i][1]]
    pb = [(DIR_NAMES[i], b.dirs[i][0], b.dirs[i][1]) for i in range(len(b.dirs)) if b.dirs[i][1]]
    na, nb = {x[0] for x in pa}, {x[0] for x in pb}
    rows.append({'axis': 'structure', 'item': 'data directories',
                 'original': ','.join(sorted(na)), 'rebuilt': ','.join(sorted(nb)),
                 'match': na == nb,
                 'kind': 'toolchain-bound'})
    sa = [s[0] for s in a.sections]
    sb = [s[0] for s in b.sections]
    rows.append({'axis': 'structure', 'item': 'section names',
                 'original': ' '.join(sa), 'rebuilt': ' '.join(sb),
                 'match': sa == sb, 'kind': 'toolchain-bound'})
    for i in range(min(len(a.sections), len(b.sections))):
        na_, va, vsz, ro, rsz, ch = a.sections[i]
        nb_, va2, vsz2, ro2, rsz2, ch2 = b.sections[i]
        rows.append({'axis': 'structure', 'item': f'section[{i}] flags',
                     'original': f"{na_} 0x{ch:08x}", 'rebuilt': f"{nb_} 0x{ch2:08x}",
                     'match': (na_ == nb_ and ch == ch2), 'kind': 'toolchain-bound'})
    return rows


# The case's own scope line: documented from evidence, deliberately not implemented, because a
# working version is the cheat (live VM takeover / integrity-check tampering), not a detector.
OUT_OF_SCOPE = {
    'NetcCheckKiller', 'BytePatcher_1byte', 'PatternRecordLoader', 'HiddenPatternRecords_Data',
    'LuaVM_Globals', 'AutoInjectDriver', 'ConfigRead_Overwack', 'HookInstaller_ClientLua',
    'OffsetResolver_Client', 'Resolver_ScanModulePattern', 'StrDecryptor_Family',
    'Hooked_LdrLoadDll_client_arm',
}


def behaviour_report(csv_path, srcdir):
    srcs = {}
    for root, _dirs, files in os.walk(srcdir):
        for fn in files:
            if os.path.splitext(fn)[1] in ('.cpp', '.h', '.def'):
                p = os.path.join(root, fn)
                srcs[p] = open(p, encoding='utf-8', errors='replace').read()
    blob = '\n'.join(f"### {k}\n{v}" for k, v in sorted(srcs.items()))
    rows = []
    import csv as _csv
    with open(csv_path, newline='', encoding='utf-8') as f:
        for row in _csv.DictReader(f):
            if 'NRTH' not in (row.get('Module') or ''):
                continue
            label = (row.get('Function Label') or '').strip()
            addr = (row.get('Address / RVA') or '').strip()
            if not label:
                continue
            ident = re.search(r'\b' + re.escape(label) + r'\b', blob)
            va = re.search(r'0x[0-9a-fA-F]{5,9}', addr)
            va_hit = bool(va and va.group(0) in blob)
            short = re.search(r'RVA 0x([0-9a-fA-F]{4,8})', addr)
            short_hit = bool(short and re.search(r'\b0x0*%s\b' % short.group(1).lstrip('0'), blob))
            if ident and not label.endswith('_Data') and not label.endswith('_Globals'):
                verdict = 'implemented (same label in the sources)'
            elif va_hit or short_hit:
                verdict = ('documented, not implemented' if label in OUT_OF_SCOPE
                           else 'evidence cited in the sources, no matching routine')
            else:
                verdict = 'not covered'
            if label in OUT_OF_SCOPE and 'documented' not in verdict:
                verdict = 'declared out of scope (case decision)'
            rows.append({'axis': 'behaviour', 'item': label, 'original': addr.split('(')[0].strip(),
                         'rebuilt': 'yes' if ident else ('cited' if (va_hit or short_hit) else 'no'),
                         'match': bool(ident), 'kind': verdict})
    return rows


def main():
    ap = argparse.ArgumentParser(description="reconstruction vs original parity report")
    ap.add_argument('original')
    ap.add_argument('rebuilt')
    ap.add_argument('--map', default=None, help='function_map.csv (default: alongside the repo)')
    ap.add_argument('--src', default='src', help='reconstruction source dir (default ./src)')
    ap.add_argument('--out', default=None, help='write a markdown report here')
    ap.add_argument('--json', action='store_true')
    ns = ap.parse_args()
    try:
        a, b = PE(ns.original), PE(ns.rebuilt)
    except (OSError, ValueError) as ex:
        print(f"[!] {ex}")
        return 2
    rows = structure_report(a, b)
    mp = ns.map
    if mp is None:
        for cand in ('../mta_blue_team_case/function_map.csv', 'mta_blue_team_case/function_map.csv',
                     os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
                         os.path.abspath(__file__)))), 'mta_blue_team_case', 'function_map.csv')):
            if os.path.isfile(cand):
                mp = cand
                break
    if mp and os.path.isfile(mp):
        rows += behaviour_report(mp, ns.src)
    else:
        print(f"[!] function map not found ({mp}); structure axis only")

    st = [r for r in rows if r['axis'] == 'structure']
    bh = [r for r in rows if r['axis'] == 'behaviour']
    sm = sum(1 for r in st if r['match'])
    if ns.json:
        print(json.dumps({'structure': st, 'behaviour': bh}, indent=2))
        return 0
    print(f"=== A. PE structure: original {os.path.basename(ns.original)} vs {os.path.basename(ns.rebuilt)} ===")
    print(f"{'field':22} {'original':30} {'rebuilt':30} {'=':2} kind")
    for r in st:
        print(f"{r['item']:22} {str(r['original'])[:30]:30} {str(r['rebuilt'])[:30]:30} "
              f"{'Y ' if r['match'] else 'n ':2} {r['kind']}")
    print(f"[*] structure match: {sm}/{len(st)}")
    fix = [r for r in st if not r['match'] and r['kind'] == 'fixable']
    tc = [r for r in st if not r['match'] and r['kind'] == 'toolchain-bound']
    print(f"[*] closable with build flags: {', '.join(r['item'] for r in fix) or 'none'}")
    print(f"[*] toolchain-bound (cannot be matched without forging compiler identity): "
          f"{', '.join(r['item'] for r in tc) or 'none'}")
    if bh:
        impl = sum(1 for r in bh if r['match'])
        decl = sum(1 for r in bh if 'out of scope' in r['kind'] or 'documented' in r['kind'])
        print(f"\n=== B. Behaviour coverage of the mapped functions ({len(bh)} rows) ===")
        for r in bh:
            print(f"  [{'+' if r['match'] else ' '}] {r['item']:34} {r['original']:26} {r['kind']}")
        print(f"[*] implemented {impl}/{len(bh)}; documented-but-declined {decl}; "
              f"not covered {len(bh) - impl - decl}")
    if ns.out:
        with open(ns.out, 'w', encoding='utf-8') as f:
            f.write(f"# Reconstruction parity report\n\n"
                    f"Original: `{ns.original}` · Rebuild: `{ns.rebuilt}`\n\n"
                    f"Structure fields matched: **{sm}/{len(st)}**\n\n"
                    f"| axis | item | original | rebuilt | match | note |\n|---|---|---|---|---|---|\n")
            for r in rows:
                f.write(f"| {r['axis']} | {r['item']} | {r['original']} | {r['rebuilt']} | "
                        f"{'✅' if r['match'] else '—'} | {r['kind']} |\n")
            fix and f.write(f"\nClosable with flags: {', '.join(r['item'] for r in fix)}\n")
            f.write(f"\nToolchain-bound: {', '.join(r['item'] for r in tc)}\n")
        print(f"[+] report -> {ns.out}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
