#!/usr/bin/env python3
"""nrth_loader_msg_parity.py — console-contract parity between NORTH LOADER.exe (original) and ours.

WHY
  The loader's user-visible work product is its console transcript: `[+] Inyectado OK clasico
  (modulo=0x%08lX)`, `[*] Export NVXHookProc en RVA 0x%08lX`, `[*] Hook instalado, despertando el hilo
  del juego...` etc. Those literal format strings are the loader's *contract* with whoever reads the
  screen (and the operator's only feedback), so reproducing them is form/contract work that is safe to
  complete and testable offline — unlike the payload's tampering behaviour.

  This tool measures that axis instead of asserting it:
    * every ASCII/NUL-terminated message string in the original's .rdata that looks like a transcript
      line (`[`-prefixed, or containing a printf conversion), and
    * every string literal passed to printf/fputs in src/north_loader.cpp,
    then reports matched / extra-in-ours / missing-in-ours.

USAGE
  python3 tools/nrth_loader_msg_parity.py [--pe working/NORTH\\ LOADER.exe]
                                          [--src src/north_loader.cpp] [--json out.json]
Exit: 0 if there is no missing/extra line beyond the documented allowlist, 3 otherwise.
"""
import argparse
import json
import os
import re
import struct
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))

# Ours deliberately prints a few extra operator-guidance lines that the original does not (the loader
# in the sample is terse). They are listed here so the metric stays honest instead of silently ignored.
ALLOWED_EXTRA = (
    '=== NORTH Loader ===',
    'DLL : %s',
    'APP : %s',
    'Pulsa ENTER para salir...',
)

# Not loader transcript at all: the sample is an MSVC *Debug*-CRT build (VCRUNTIME140D/ucrtbased per the
# import table), so its .rdata also carries the runtime's own message formats. They are excluded from the
# denominator explicitly - silently dropping them would inflate the parity number.
CRT_NOISE = (
    re.compile(r'%p.*%zd'),                       # _CxxThrowException / debug report format
    re.compile(r'^Run-Time Check Failure'),       # /GS+RTC runtime banner
    re.compile(r'^SOFTWARE\\Microsoft'),          # registry path constants
)


def is_crt_noise(s):
    return any(rx.search(s) for rx in CRT_NOISE)


def sec_table(d):
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    opt = pe + 24
    optsize = struct.unpack_from('<H', d, pe + 20)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    out = []
    for i in range(nsec):
        o = opt + optsize + i * 40
        nm = d[o:o + 8].split(b'\0')[0].decode('latin1')
        vsz, va, rsz, ro = struct.unpack_from('<4I', d, o + 8)
        out.append((nm, va, vsz, ro, rsz))
    return out


def sample_messages(path):
    d = open(path, 'rb').read()
    msgs = []
    for nm, va, vsz, ro, rsz in sec_table(d):
        if nm not in ('.rdata', '.data'):
            continue
        blob = d[ro:ro + rsz]
        for m in re.finditer(rb'[\x20-\x7e\xa1-\xff]{6,}', blob):
            s = m.group().decode('latin1')
            if not (s.startswith('[') or '%' in s):
                continue
            if not re.search(r'%[-0-9.#l]*[dsxulXlf]', s) and not s.startswith(('[+]', '[-]', '[!]', '[*]')):
                continue
            msgs.append((nm, ro + m.start(), va + m.start(), s.rstrip('\\n').replace('\\n', '\n')))
    return msgs


def our_literals(path):
    src = open(path, encoding='utf-8', errors='replace').read()
    out = []
    for m in re.finditer(r'(printf|fputs|puts)\s*\(\s*((?:"(?:[^"\\]|\\.)*"\s*)+)', src):
        chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(2))
        s = ''.join(chunks)
        s = s.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"').replace('%%', '%')
        out.append((src[:m.start()].count('\n') + 1, s.rstrip('\n')))
    return out


def norm(s):
    return re.sub(r'\s+', ' ', s).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pe', default=os.path.join(ROOT, 'working', 'NORTH LOADER.exe'))
    ap.add_argument('--src', default=os.path.join(ROOT, 'recovered_or_reconstructed_project', 'src',
                                                   'north_loader.cpp'))
    ap.add_argument('--json')
    ns = ap.parse_args()
    if not os.path.exists(ns.pe):
        print("[-] sample loader not found: %s (extract NORTH.zip first)" % ns.pe)
        return 2
    theirs = sample_messages(ns.pe)
    ours = our_literals(ns.src)
    tset = {norm(t[3]): t for t in theirs if not is_crt_noise(norm(t[3]))}
    crt = [t for t in theirs if is_crt_noise(norm(t[3]))]
    oset = {norm(s): ln for ln, s in ours}
    matched = sorted(set(tset) & set(oset))
    extra = [k for k in sorted(oset) if k not in tset and not any(k.startswith(a.rstrip('\n')) for a in ALLOWED_EXTRA)]
    missing = [k for k in sorted(tset) if k not in oset]
    print("== loader console-contract parity: %s vs %s" % (os.path.basename(ns.pe), os.path.basename(ns.src)))
    print("   original transcript lines: %d | our printf/fputs literals: %d   (CRT-internal formats "
          "excluded from the sample side: %d)" % (len(tset), len(oset), len(crt)))
    print("   matched exactly: %d" % len(matched))
    for k in matched:
        print("      + %-62s (their .rdata VA 0x%08x / our line %d)"
              % (k[:62], 0x400000 + tset[k][2], oset[k]))
    if extra:
        print("   extra in ours (not printed by the original):")
        for k in extra:
            print("      ! %s  (line %d)" % (k[:70], oset[k]))
    if missing:
        print("   transcript lines the original prints that we do not:")
        for k in missing:
            print("      - %s  (their VA 0x%08x)" % (k[:70], 0x400000 + tset[k][2]))
    if ns.json:
        json.dump({'sample': os.path.relpath(ns.pe, ROOT), 'source': os.path.relpath(ns.src, ROOT),
                   'theirs': len(tset), 'ours': len(oset), 'matched': matched,
                   'extra_in_ours': extra, 'missing_in_ours': missing},
                  open(ns.json, 'w', encoding='utf-8'), indent=2, ensure_ascii=False)
        print("   json -> %s" % ns.json)
    ok = not extra and not missing
    print("[=] %s" % ("contract parity: every original transcript line reproduced, no undeclared extras"
                       if ok else "differences listed above"))
    return 0 if ok else 3


if __name__ == '__main__':
    sys.exit(main())
