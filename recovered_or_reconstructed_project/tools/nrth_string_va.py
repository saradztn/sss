#!/usr/bin/env python3
"""Locate / verify string addresses in a PE image - dependency-free.

The case docs originally carried plain-.rdata string addresses written as `ImageBase + file offset`
(which is 0x1000 short of the real VA in this module, and in several places had one extra zero digit:
`0x1000e90d8`).  This tool exists so any such claim can be settled in one command instead of by eye.

Usage
  nrth_string_va.py <pe> <needle> [...]                  find: print offset / RVA / VA per occurrence
  nrth_string_va.py <pe> --check "0x100ea0d8=North Cheat"  verify: VA must hold exactly those bytes
  nrth_string_va.py <pe> --audit-docs [--also <pe2>] <file> [...]
        verify every "<string>" ... 0xADDR claim in docs/sources.  Verdicts: OK (the claim is a
        verified VA of a string on that line), OK-OFF (a file offset and the line says so), INFO (the
        address is code/IAT/global data, or belongs to --also's module: not a string-location claim),
        BAD (the claim points at other bytes - fix the doc).
Exit code: 0 if nothing is BAD, 1 if a claim is BAD/FAIL, 2 on usage or IO errors.
"""
import re
import struct
import sys

# Quote handling: a token is `"..."` or a backtick pair.  Single quotes are deliberately excluded - an
# apostrophe in prose and a char literal in C++ code would otherwise pair up into bogus "needles".
_TOK = r'(?:["`][^"`\n;]{1,48}["`])'
IGNORE = re.compile(r"^\.(rdata|data|text|textbss|reloc|rsrc|bss|eh_fram)$|^(RVA|VA|PE32|x86|High|Medium|Low)$")
INFO_WORDS = re.compile(r"\b(RVA|VA|export|ordinal|import|IAT|thunk|slot|global|trampoline|flag|state|field|"
                        r"call|handler|detour|site|function|prologue|hook|\u0627\u0644\u0639\u0644\u0645|"
                        r"\u0645\u062a\u063a\u064a\u0631|\u0627\u0644\u0625\u0632\u0627\u062d\u0629)\b")
ADDR = r"0x([0-9a-fA-F]{4,9})"
ADDR_RX = re.compile(ADDR)
PAIR_A = re.compile(_TOK + r"[^0-9\n]{0,24}" + ADDR)
PAIR_B = re.compile(ADDR + r"[^\n]{0,8}" + _TOK)


def quoted_tokens(line):
    """Every `"..."` / backtick token of >= 5 characters on the line.

    Quotes are paired greedily left to right.  A regex that just matches "quote ... quote" also pairs a
    closing quote with the next opening quote, which turns `..., i);   // ` into a fake string.
    """
    out, start, sch = [], -1, ''
    for i, ch in enumerate(line):
        if ch not in ('"', '`'):
            continue
        if start < 0:
            start, sch = i, ch
        elif ch == sch:
            tok = line[start + 1:i]
            # markdown table cells sit between two backtick spans, and code fragments between two
            # string literals; neither is a claim about where a string lives, so they are dropped
            if 5 <= len(tok) <= 48 and '\n' not in tok and '|' not in tok and tok == tok.strip():
                out.append(tok.replace('\\\\', '\\'))
            start, sch = -1, ''
    return out


def parse_pe(d):
    e = struct.unpack_from('<I', d, 0x3c)[0]
    if d[e:e + 4] != b'PE\0\0':
        raise ValueError("not a PE image")
    base = struct.unpack_from('<I', d, e + 52)[0]
    n = struct.unpack_from('<H', d, e + 6)[0]
    o = e + 24 + struct.unpack_from('<H', d, e + 20)[0]
    S = []
    for i in range(n):
        s = d[o + i * 40:o + i * 40 + 40]
        if len(s) < 40:
            break
        # header order at +8 is VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData
        vsz, va, rsz, ro = struct.unpack_from('<IIII', s, 8)
        S.append({'name': s[:8].rstrip(b'\0').decode('latin1'), 'vsz': vsz, 'va': va,
                  'rsz': rsz, 'ro': ro})
    return base, S


def off_to_rva(S, o):
    for x in S:
        if x['rsz'] and x['ro'] <= o < x['ro'] + x['rsz']:
            return x['va'] + (o - x['ro']), x['name']
    return None, None


def rva_to_off(S, r):
    for x in S:
        if x['vsz'] and x['va'] <= r < x['va'] + x['vsz']:
            o = x['ro'] + (r - x['va'])
            if o < x['ro'] + x['rsz']:
                return o, x['name']
    return None, None


def section_of_rva(S, r):
    for x in S:
        if x['vsz'] and x['va'] <= r < x['va'] + x['vsz']:
            return x['name']
    return None


def occurrences(d, needle):
    b = needle.encode('latin1', 'replace')
    out, i = [], d.find(b)
    while i != -1:
        out.append(i)
        i = d.find(b, i + 1)
    return out, b


def main():
    if len(sys.argv) < 3:
        print(__doc__.strip())
        return 2
    path = sys.argv[1]
    try:
        d = open(path, 'rb').read()
        base, S = parse_pe(d)
    except (OSError, ValueError) as ex:
        print(f"[!] {path}: {ex}")
        return 2
    args = sys.argv[2:]
    if args[0] == '--audit-docs':
        also = None
        rest = args[1:]
        if rest and rest[0] == '--also':
            try:
                d2 = open(rest[1], 'rb').read()
                also = (d2,) + parse_pe(d2)
                rest = rest[2:]
            except (OSError, ValueError) as ex:
                print(f"[!] --also: {ex}")
                return 2
        return audit_docs(d, base, S, rest, also)
    if args[0] == '--check':
        bad = 0
        for a in args[1:]:
            va, _, needle = a.partition('=')
            try:
                t = int(va, 16) - base
            except ValueError:
                print(f"[!] bad address {va}")
                bad += 1
                continue
            off, sec = rva_to_off(S, t)
            got = d[off:off + len(needle)] if off is not None else b''
            ok = got == needle.encode('latin1', 'replace')
            print(f"{'[ok]  ' if ok else '[FAIL]'} {va} -> {('.' + sec) if sec else 'unmapped'} "
                  f"rva=0x{t:x} bytes={got[:32].decode('latin1')!r} "
                  f"expect={needle!r}")
            bad += 0 if ok else 1
        return 1 if bad else 0

    for a in args:
        hits, b = occurrences(d, a)
        for i in hits:
            rva, sec = off_to_rva(S, i)
            print(f"{a!r:34} off=0x{i:<7x} rva=0x{rva:x} va=0x{base + rva:x} .{sec}")
        if not hits:
            print(f"{a!r:34} NOT FOUND in the raw image "
                  f"(encrypted at rest? decode it: nrth_audit decode <pe> --rva ... )")
    return 0


def audit_docs(d, base, S, files, also=None):
    """See the usage string.  Kept deliberately conservative: it only reports a BAD when the claim
    looks like a string location and the bytes there say otherwise."""
    imgs = [(d, base, S)]
    if also:
        imgs.append(also)

    def vas_of(img, needle):
        dd, bb, SS = img
        hits, b = occurrences(dd, needle)
        out = set()
        for o in hits:
            rva, _ = off_to_rva(SS, o)
            if rva is not None:
                out.add(bb + rva)
        return out, set(hits)

    pairs, seen = [], set()
    for f in files:
        try:
            txt = open(f, encoding='utf-8', errors='replace').read()
        except OSError as ex:
            print(f"[!] {f}: {ex}")
            return 2
        for ln, line in enumerate(txt.split('\n'), 1):
            for rx in (PAIR_A, PAIR_B):
                for m in rx.finditer(line):
                    toks = quoted_tokens(m.group(0))
                    if not toks:
                        continue
                    needle = toks[0]
                    # PAIR_A ends with the address, PAIR_B starts with it
                    a = ADDR_RX.findall(m.group(0))
                    want = int(a[-1] if rx is PAIR_A else a[0], 16)
                    key = (f, ln, needle, want)
                    if key in seen:
                        continue
                    seen.add(key)
                    pairs.append((f, ln, needle, want, line))

    ok = offok = info = bad = 0
    for f, ln, needle, want, line in pairs:
        if IGNORE.match(needle):
            continue
        allvas, allofts = set(), set()
        # any string on the same line may be the claim's subject (prose lists several per line)
        for other in quoted_tokens(line):
            v, o = vas_of(imgs[0], other)
            allvas |= v
            allofts |= o
            if also:
                v2, o2 = vas_of(imgs[1], other)
                allvas |= v2
                allofts |= o2
        if not allvas:
            continue
        if want in allvas:
            ok += 1
            continue
        if want in allofts and (re.search(r"off 0x|file offset|offset |الإزاحة", line)):
            print(f"OK-OFF {f}:{ln}  {needle!r} given as file offset 0x{want:x}")
            offok += 1
            continue
        rva = want - base
        sec = section_of_rva(S, rva) if 0 <= rva < 0x200000 else None
        in_code = sec == '.text' or want == base
        if also and not in_code:
            d2, b2, S2 = also
            r2 = want - b2
            in_code = section_of_rva(S2, r2) == '.text' or want == b2
        if in_code or sec or INFO_WORDS.search(line):
            info += 1                      # code / IAT / global / other-module address
            continue
        bad += 1
        near = ', '.join('0x%x' % v for v in sorted(allvas)[:4])
        print(f"BAD  {f}:{ln}  {needle!r} claimed 0x{want:x}; bytes there are not that string; "
              f"candidate VA(s) on this line: {near or 'none'}")
    print(f"[*] {len(pairs)} string/address claim(s) in {len(files)} file(s): {ok} ok, "
          f"{offok} labelled-offset, {info} code/data-site (info), {bad} BAD")
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
