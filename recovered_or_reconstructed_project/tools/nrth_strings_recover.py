#!/usr/bin/env python3
"""nrth_strings_recover.py — recover the NORTH/NVX family's obfuscated string records.

Read-only blue-team analysis tool. It does not execute, patch, hook or inject anything:
it parses PE bytes and re-implements the sample's OWN string codec, so defenders can
decode a sample's (or a key-rotated variant's) hidden strings and code-signature
patterns without a disassembler session.

Verified against NRTH.dll, SHA-256
947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861:

  Codec    plain[p] = cipher[p] XOR ((p - K) & 0xFF)          (positional XOR, per record)
           K = 0x2D (most records) / 0x20 (short 8-byte records, e.g. "netc.dll")
  One-shot a flag byte behind the buffer is cleared after decoding
           (`cmp byte ptr [this+F],0` ... `mov byte ptr [this+F],0`), so the same
           record is never decrypted twice; payload length L = F - 1.
  Sizes    specialised decryptors, one per record length:
           0x10007640 L=80, 0x10007780 L=52, 0x100078d0 L=10 (scalar byte loop),
           0x10007900 L=12, 0x1000bc00 L=8 (K=0x20), 0x1000bc80 L=30 (K=0x20), ...
  Fill     MSVC Debug codegen materialises a record either directly in .rdata/.data
           (decrypted in place) or on the stack, gathered by the compiler from 16-byte
           blocks plus inline immediates:
               movaps xmm0, [imm32]            ; 16 bytes of ciphertext
               movups [ebp+d32], xmm0
               mov  dword [ebp+d32|d8], imm32  ; tail bytes of short records
               mov  word  [ebp+d32], 0x0100    ; NUL + one-shot flag
           so recovery = rebuild the buffer from the fill window that precedes
           `call <decryptor>`, then decrypt. We emulate the codec, not the program.

Why defenders care: the recovered plaintexts are the exact byte-signature patterns the
tool pattern-scans inside client.dll / d3d9.dll / netc.dll (they are not exported by
name), plus its registry/file/config paths — i.e. the most durable detection anchors,
still present after string renaming of the UI. Reusable as integrity signatures:
see ../mta_blue_team_case/detection/audit_tool.md.

Requires: pefile + capstone (pip install pefile capstone).

Usage
    python3 nrth_strings_recover.py <PE-file> [--json out.json] [--min-len 4] [--quiet]
"""
import argparse
import json
import struct
import sys

try:
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
except ImportError:
    sys.exit("[!] needs `pip install pefile capstone`")

FAMILY_KEYS = (0x2D, 0x20)      # keys observed in this sample; also brute-forced below
MAX_RECORD = 0x100              # sanity cap on record payload length
WINDOW = 90                     # instructions scanned back from the decryptor call


class Image:
    def __init__(self, path):
        self.pe = pefile.PE(path)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.text = next(s for s in self.pe.sections
                         if s.Name.rstrip(b"\x00") == b".text")

    def read_va(self, va, n):
        try:
            off = self.pe.get_offset_from_rva(va - self.base)
        except Exception:
            return b"\x00" * n
        d = bytes(self.pe.__data__[off:off + n])
        return d + b"\x00" * (n - len(d))

    def code(self):
        return bytes(self.text.get_data())

    def va0(self):
        return self.base + self.text.VirtualAddress


def find_decryptors(code):
    """Structural match of the per-length one-shot decryptors -> {offset: (L, K)}.

    push <r> / mov <r>, ecx / cmp byte ptr [<r>+F], 0 / je ... / <xor loop> /
    mov byte ptr [<r>+F], 0.   L = F - 1, K from the first `lea x,[y-K]` when the
    decryptor uses a scalar loop; SSE variants load the key lanes from .rdata, so K
    is not recovered here — it is brute-forced at decode time instead.
    """
    out = {}
    for i in range(len(code) - 6):
        b = code[i:i + 4]
        if not (b[0] == 0x80 and b[1] in (0x7B, 0x7D, 0x7E, 0x7F) and b[3] == 0x00):
            continue
        nxt = code[i + 4:i + 6]
        if not (nxt[:1] == b"\x74" or nxt[:2] == b"\x0f\x84"):
            continue
        length = b[2] - 1
        if not (4 <= length <= MAX_RECORD):
            continue
        entry = None
        for back in range(1, 10):                # rewind over `mov <r>, ecx` to `push <r>`
            if code[i - back] in (0x53, 0x55, 0x56, 0x57):
                entry = i - back
                break
        if entry is not None:
            out.setdefault(entry, length)
    return out


def decode(buf, key):
    return bytes(buf[p] ^ ((p - key) & 0xFF) for p in range(len(buf)))


def best_key(buf):
    """Key producing the longest printable decode; family keys win ties."""
    best, bk, score = b"", None, -1
    for key in range(256):
        txt = decode(buf, key).split(b"\x00")[0]
        if len(txt) < 4 or not all(32 <= c < 127 for c in txt):
            continue
        s = len(txt) + (2 if key in FAMILY_KEYS else 0)
        if s > score:
            best, bk, score = txt, key, s
    return best, bk


def func_bounds(ins, addr):
    """[start, end) of the function containing `addr` (MSVC `push ebp; mov ebp,esp`
    prologue, terminated by the first ret/int3 after addr). Heuristic, analysis only."""
    start = None
    for n, m in enumerate(ins):
        if m.address > addr:
            break
        if m.mnemonic == "push" and m.op_str == "ebp" and n + 1 < len(ins) \
                and ins[n + 1].mnemonic == "mov" and ins[n + 1].op_str == "ebp, esp" \
                and ins[n + 1].address <= addr:
            start = m.address
    end = None
    for m in ins:
        if m.address <= addr:
            continue
        if m.mnemonic in ("ret", "int3"):
            end = m.address
            break
    return start, (end or addr + 0x400)


def recover(img):
    """Return ({decryptor_va: len}, [records]) — records rebuilt from their fill window."""
    code, va0 = img.code(), img.va0()
    decs = {va0 + off: L for off, L in find_decryptors(code).items()}
    ins = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, va0))
    pos = {i.address: n for n, i in enumerate(ins)}
    records = []

    for n, i in enumerate(ins):
        if i.mnemonic != "call":
            continue
        try:
            tgt = int(i.op_str, 16)
        except ValueError:
            continue
        if tgt not in decs:
            continue
        reclen = decs[tgt]

        fills, bases = [], []
        for m in reversed(ins[max(0, n - WINDOW):n]):
            b = m.bytes
            if m.address == i.address:
                continue
            if m.mnemonic in ("call", "ret"):
                break
            if b[0] == 0x0f and b[1] in (0x28, 0x10) and b[2] in (0x05, 0x0d) \
                    and m.op_str.startswith("xmm"):
                fills.append(("block", struct.unpack("<I", b[3:7])[0]))
            elif b[0] == 0x0f and b[1] in (0x11, 0x10) and b[2] == 0x85:
                fills.append(("dst", struct.unpack("<i", b[3:7])[0]))
            elif b[:2] == b"\xc7\x85":
                fills.append(("imm32", struct.unpack("<i", b[2:6])[0], struct.unpack("<I", b[6:10])[0]))
            elif b[:3] == b"\x66\xc7\x85":
                fills.append(("imm16", struct.unpack("<i", b[3:7])[0], struct.unpack("<H", b[7:9])[0]))
            elif b[:2] == b"\xc7\x45":
                fills.append(("imm32", struct.unpack("<b", b[2:3])[0], struct.unpack("<I", b[3:7])[0]))
            elif b[:2] in (b"\x8d\x8d", b"\x8d\x4d", b"\x8d\xb5") and m.op_str.startswith("ecx, [ebp"):
                fills.append(("base", struct.unpack("<i", b[2:6])[0] if b[1] in (0x8d, 0xb5)
                              else struct.unpack("<b", b[2:3])[0]))
            elif b[0] == 0xb9 and m.op_str.startswith("ecx, 0x10"):
                fills.append(("base_abs", struct.unpack("<I", b[1:5])[0]))
        fills.reverse()
        bases = [f[1] if f[0] != "base_abs" else ("abs", f[1]) for f in fills if f[0].startswith("base")]
        fills = [f for f in fills if not f[0].startswith("base")]
        if not fills or not bases:
            continue

        seen = set()
        for cand in bases:
            in_place = isinstance(cand, tuple)
            if in_place:
                blob = img.read_va(cand[1], reclen)
                txt, key = best_key(blob)
                if txt and txt not in seen:
                    seen.add(txt)
                    records.append(dict(site=i.address, decryptor=tgt, len=reclen, key=key,
                                        kind="in-place@0x%08x" % cand[1],
                                        text=txt.decode("ascii", "replace")))
                continue
            buf, pend = {}, None
            for f in fills:
                if f[0] == "block":
                    pend = f[1]
                elif f[0] == "dst" and pend is not None:
                    blk = img.read_va(pend, 16)
                    for t in range(16):
                        buf[f[1] - cand + t] = blk[t]
                    pend = None
                elif f[0] == "imm32":
                    for t in range(4):
                        buf[f[1] - cand + t] = (f[2] >> (8 * t)) & 0xFF
                elif f[0] == "imm16":
                    for t in range(2):
                        buf[f[1] - cand + t] = (f[2] >> (8 * t)) & 0xFF
            buf = {k: v for k, v in buf.items() if 0 <= k < reclen}
            if len(buf) < 4:
                continue
            txt, key = best_key(bytes(buf.get(p, 0) for p in range(reclen)))
            if txt and txt not in seen:
                seen.add(txt)
                records.append(dict(site=i.address, decryptor=tgt, len=reclen, key=key,
                                    kind="stack[ebp%+d]" % cand,
                                    text=txt.decode("ascii", "replace")))
    return decs, records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pe")
    ap.add_argument("--json", default=None)
    ap.add_argument("--min-len", type=int, default=4)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    img = Image(a.pe)
    decs, records = recover(img)
    uniq = {}
    for r in records:
        if len(r["text"]) >= a.min_len:
            uniq.setdefault(r["text"], []).append(r)
    ordered = sorted(uniq, key=lambda x: (-len(x), x))

    if not a.quiet:
        print("[*] sample          : %s" % a.pe)
        print("[*] image base      : 0x%08x" % img.base)
        print("[*] decryptors found: %d (record lengths %s)"
              % (len(decs), ", ".join(str(v) for v in sorted(set(decs.values())))))
        print("[*] records         : %d distinct plaintexts" % len(ordered))
        for t in ordered:
            r = uniq[t][0]
            print("  [%3d] key=0x%02X dec=0x%08x %-20s x%-2d %s"
                  % (len(t), r["key"], r["decryptor"], r["kind"], len(uniq[t]), repr(t)))

    if a.json:
        payload = {
            "file": a.pe,
            "image_base": "0x%08x" % img.base,
            "codec": "plain[p] = cipher[p] XOR ((p - K) & 0xFF); one-shot flag at record+F, L = F-1",
            "decryptors": {"0x%08x" % k: v for k, v in sorted(decs.items())},
            "records": [{"text": t, "len": len(t), "key": "0x%02X" % uniq[t][0]["key"],
                         "decryptor": "0x%08x" % uniq[t][0]["decryptor"],
                         "site": "0x%08x" % uniq[t][0]["site"],
                         "kind": uniq[t][0]["kind"], "sites": len(uniq[t])} for t in ordered],
        }
        with open(a.json, "w") as f:
            json.dump(payload, f, indent=2)
        print("[+] json -> %s" % a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
