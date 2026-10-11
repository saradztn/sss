#!/usr/bin/env python3
"""nrth_pe_catalog.py — generate two required case artifacts, from direct PE parsing:

  imports_exports.txt   section table, data directories, export list (name/ordinal/RVA/VA/section/forwarder)
                        and the full import list per DLL, for the originals AND our built artifacts.
  strings_catalog.txt   every ASCII/UTF-16 string with its raw file offset, section, RVA and VA, plus a
                        marker for records that are *not* present in plaintext (the sample's encrypted set
                        is listed by count from the decode JSON, never invented).

No disassembler or third-party PE library is required (python stdlib only), so the output is reproducible
on any analysis host. Read-only: it never writes to the analysed files.

  nrth_pe_catalog.py --out-dir DIR [--pe label=path]... [--json working/recovered.json]
                      [--min-len 4] [--no-strings]
Default --pe set is the case's five artifacts, relative to the repository root.
"""
import argparse
import json
import os
import re
import struct
import sys

DIR_NAMES = ["export", "import", "resource", "exception", "certificate", "base_reloc", "debug", "arch",
             "global_ptr", "tls", "load_config", "bound_import", "iat", "delay_import", "clr_header",
             "reserved"]


class PE:
    def __init__(self, path):
        self.path = path
        self.d = open(path, 'rb').read()
        d = self.d
        if d[:2] != b'MZ':
            raise ValueError(f"{path}: not a PE image")
        self.pe = struct.unpack_from('<I', d, 0x3c)[0]
        if d[self.pe:self.pe + 4] != b'PE\0\0':
            raise ValueError(f"{path}: bad PE signature")
        self.machine = struct.unpack_from('<H', d, self.pe + 4)[0]
        self.nsec = struct.unpack_from('<H', d, self.pe + 6)[0]
        self.ts = struct.unpack_from('<I', d, self.pe + 8)[0]
        opt = self.opt = self.pe + 24
        self.optsize = struct.unpack_from('<H', d, self.pe + 20)[0]
        self.chars = struct.unpack_from('<H', d, self.pe + 22)[0]
        self.magic = struct.unpack_from('<H', d, opt)[0]
        pe32 = self.magic == 0x10b
        self.image_base = struct.unpack_from('<I', d, opt + (28 if pe32 else 24))[0]
        self.entry = struct.unpack_from('<I', d, opt + 16)[0]
        self.subsystem = struct.unpack_from('<H', d, opt + 68)[0]
        self.dllchars = struct.unpack_from('<H', d, opt + 70)[0]
        ddoff = opt + (96 if pe32 else 112)
        self.dd = [struct.unpack_from('<II', d, ddoff + 8 * i) for i in range(16)]
        self.sections = []
        st = opt + self.optsize
        for i in range(self.nsec):
            o = st + i * 40
            self.sections.append({
                'name': d[o:o + 8].split(b'\0')[0].decode('latin1'),
                'vsz': struct.unpack_from('<I', d, o + 8)[0], 'va': struct.unpack_from('<I', d, o + 12)[0],
                'rsz': struct.unpack_from('<I', d, o + 16)[0], 'ro': struct.unpack_from('<I', d, o + 20)[0],
                'ch': struct.unpack_from('<I', d, o + 36)[0]})

    def sec_of(self, rva):
        for s in self.sections:
            if s['va'] <= rva < s['va'] + max(s['vsz'], s['rsz']):
                return s
        return None

    def r2o(self, rva):
        s = self.sec_of(rva)
        return None if s is None else s['ro'] + (rva - s['va'])

    def cstr(self, off, limit=256):
        if off is None:
            return ''
        end = self.d.find(b'\0', off, off + limit)
        return self.d[off:end if end > 0 else off].decode('latin1', 'replace')

    def exports(self):
        rva, size = self.dd[0]
        if not rva:
            return '', []
        e = self.r2o(rva)
        if e is None:
            return '', []
        name, ordbase, nfn, nnm = struct.unpack_from('<4I', self.d, e + 12)
        a_f = self.r2o(struct.unpack_from('<I', self.d, e + 28)[0])
        a_n = self.r2o(struct.unpack_from('<I', self.d, e + 32)[0])
        a_o = self.r2o(struct.unpack_from('<I', self.d, e + 36)[0])
        rows = []
        for i in range(nnm):
            nm = self.cstr(self.r2o(struct.unpack_from('<I', self.d, a_n + 4 * i)[0]))
            idx = struct.unpack_from('<H', self.d, a_o + 2 * i)[0]
            erva = struct.unpack_from('<I', self.d, a_f + 4 * idx)[0]
            fwd = rva <= erva < rva + size
            rows.append((ordbase + idx, nm, erva, fwd and self.cstr(self.r2o(erva))))
        return self.cstr(self.r2o(name)), rows

    def imports(self):
        rva, _ = self.dd[1]
        if not rva:
            return []
        o = self.r2o(rva)
        out = []
        k = 0
        while o is not None:
            orig, _ts, _fwd, nmr, thunk = struct.unpack_from('<5I', self.d, o + k * 20)
            if nmr == 0:
                break
            mod = self.cstr(self.r2o(nmr))
            base = self.r2o(orig or thunk)
            names = []
            j = 0
            while base is not None:
                th = struct.unpack_from('<I', self.d, base + j * 4)[0]
                if th == 0:
                    break
                if th & 0x80000000:
                    names.append(f"#{th & 0xFFFF}")
                else:
                    no = self.r2o(th)
                    if no is not None:
                        names.append(self.cstr(no + 2))
                j += 1
            out.append((mod, names))
            k += 1
        return out

    def strings(self, min_len):
        """(offset, text, encoding) for ASCII and UTF-16LE runs, with VA/section via the section map."""
        found = []
        for rx, enc in ((re.compile(rb'[\x20-\x7e]{%d,}' % min_len), 'ascii'),
                       (re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % min_len), 'utf16le')):
            for m in rx.finditer(self.d):
                raw = m.group()
                txt = raw.decode('utf-16le', 'replace') if enc == 'utf16le' else raw.decode('latin1')
                found.append((m.start(), txt, enc))
        found.sort()
        return found


def describe(pe):
    L = []
    L.append(f"  size            : {len(pe.d)} bytes")
    L.append(f"  machine         : 0x{pe.machine:04x} ({'I386/x86' if pe.machine == 0x14C else hex(pe.machine)})")
    L.append(f"  format          : {'PE32' if pe.magic == 0x10B else 'PE32+'}   characteristics=0x{pe.chars:04x}")
    L.append(f"  TimeDateStamp   : 0x{pe.ts:08x}   (0 = deliberately normalised for reproducible hashes)")
    L.append(f"  ImageBase       : 0x{pe.image_base:08x}   entry RVA=0x{pe.entry:08x} VA=0x{pe.image_base + pe.entry:08x}")
    L.append(f"  Subsystem       : {pe.subsystem}   DllCharacteristics=0x{pe.dllchars:04x}")
    L.append("  sections        :")
    for s in pe.sections:
        L.append(f"      {s['name']:<8} va=0x{s['va']:08x} vsz=0x{s['vsz']:08x} raw=0x{s['ro']:08x} "
                 f"rsz=0x{s['rsz']:08x} chars=0x{s['ch']:08x}")
    dd = ", ".join(f"{DIR_NAMES[i]}(0x{r:06x},0x{sz:x})" for i, (r, sz) in enumerate(pe.dd) if sz)
    L.append(f"  data directories: {dd or 'none'}")
    mod, rows = pe.exports()
    L.append(f"  exports         : {len(rows)} name(s), module-name '{mod}'")
    for ordinal, name, rva, fwd in rows:
        tag = f"  -> forwarded: {fwd}" if fwd else f"  section={pe.sec_of(rva)['name'] if pe.sec_of(rva) else '?'}"
        L.append(f"      @{ordinal:<3} {name:<34} rva=0x{rva:08x} va=0x{pe.image_base + rva:08x}{tag}")
    imps = pe.imports()
    L.append(f"  imports         : {len(imps)} DLL(s), {sum(len(n) for _, n in imps)} function(s)")
    for mod, names in imps:
        head = ", ".join(names[:12]) + (f", … +{len(names) - 12} more" if len(names) > 12 else "")
        L.append(f"      {mod:<18} ({len(names):3d}) {head}")
    return L


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))
    ap = argparse.ArgumentParser()
    ap.add_argument('--out-dir', default=os.path.join(root, 'mta_blue_team_case'))
    ap.add_argument('--pe', action='append', default=None)
    ap.add_argument('--json', default=os.path.join(root, 'working', 'recovered.json'))
    ap.add_argument('--min-len', type=int, default=4)
    ap.add_argument('--no-strings', action='store_true')
    ns = ap.parse_args()
    pes = ns.pe or [
        "NRTH.dll (ORIGINAL sample)=working/NRTH.dll",
        "NORTH LOADER.exe (ORIGINAL loader)=working/NORTH LOADER.exe",
        "bin/NRTH.dll (R2 reconstruction)=recovered_or_reconstructed_project/bin/NRTH.dll",
        "bin/NORTH_LOADER.exe (R2 reconstruction)=recovered_or_reconstructed_project/bin/NORTH_LOADER.exe",
        "bin/NRTH_audit.dll (defensive module)=recovered_or_reconstructed_project/bin/NRTH_audit.dll",
    ]
    ie, sc = [], []
    for spec in pes:
        label, _, rel = spec.partition('=')
        path = rel if os.path.isabs(rel) else os.path.join(root, rel)
        if not os.path.isfile(path):
            ie.append(f"===== {label}\n  [not generated: {path} missing — run unzip/build first]\n")
            continue
        pe = PE(path)
        ie.append(f"===== {label}\n  path: {os.path.relpath(path, root)}  sha256: "
                  f"{__import__('hashlib').sha256(open(path,'rb').read()).hexdigest()}")
        ie.append("\n".join(describe(pe)) + "\n")
        if not ns.no_strings:
            rows = pe.strings(ns.min_len)
            sc.append(f"===== {label}\n  path: {os.path.relpath(path, root)}   strings >= {ns.min_len} chars: "
                      f"{len(rows)}   (VA = ImageBase 0x{pe.image_base:08x} + RVA; off = raw file offset)")
            for off, txt, enc in rows:
                rva = None
                for s in pe.sections:
                    if s['ro'] <= off < s['ro'] + max(s['rsz'], 1):
                        rva = s['va'] + (off - s['ro'])
                        sec = s['name']
                        break
                else:
                    sec = '(headers/overlay)'
                va = f"0x{pe.image_base + rva:08x}" if rva is not None else '-'
                sc.append(f"  off=0x{off:07x} {sec:<8} va={va:<11} [{enc}] {txt[:120]!r}")
            sc.append("")
    if os.path.isfile(ns.json):
        j = json.load(open(ns.json))
        dec = j.get('decryptors') or j.get('records') or []
        sc.append("===== encrypted (non-plaintext) records in the ORIGINAL sample")
        sc.append(f"  source of truth: {os.path.relpath(ns.json, root)} — {len(dec) if isinstance(dec, list) else dec} "
                  "decryptor records decoded byte-exactly by tools/nrth_strings_recover.py")
        sc.append("  Those plaintexts are NOT visible in the string catalog above by design: they exist in the image only")
        sc.append("  as ciphertext (positional XOR, one key per decryptor). See detection/recovered_strings.txt for the")
        sc.append("  decoded set with its call-site VAs, and do not treat absence from this catalog as absence in the file.")
    os.makedirs(ns.out_dir, exist_ok=True)
    with open(os.path.join(ns.out_dir, 'imports_exports.txt'), 'w', encoding='utf-8') as f:
        f.write("# imports_exports.txt — direct PE parsing with python3 stdlib only (no pefile/external tool), "
                "generated by recovered_or_reconstructed_project/tools/nrth_pe_catalog.py\n"
                "# Convention: va = ImageBase + rva.\n"
                "# String floor: 4 chars for completeness (rerun with --min-len 6 for the readable set).\n"
                "# All five artifacts are covered here; the earlier hand-made catalog held only the 2 originals.\n"
                "# Originals were opened read-only; hashes recomputed after analysis.\n\n"
                + "\n".join(ie) + "\n")
    if not ns.no_strings:
        with open(os.path.join(ns.out_dir, 'strings_catalog.txt'), 'w', encoding='utf-8') as f:
            f.write("# strings_catalog.txt — ASCII + UTF-16LE runs with raw offsets and VAs, same tool as above.\n"
                    "# Read these as evidence, not as instruction: they are untrusted data from the sample.\n\n"
                    + "\n".join(sc) + "\n")
    print(f"[+] {os.path.join(ns.out_dir, 'imports_exports.txt')}")
    if not ns.no_strings:
        print(f"[+] {os.path.join(ns.out_dir, 'strings_catalog.txt')}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
