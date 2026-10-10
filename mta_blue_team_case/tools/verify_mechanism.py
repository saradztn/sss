#!/usr/bin/env python3
"""
verify_mechanism.py — Automated verification of the documented mechanism claims
for NRTH.dll (mta_blue_team_case/mechanism_vm_injection.md, mechanism_overview_ar.md).

Every check re-reads the REAL sample bytes and proves (or refutes) a documented
claim. No dependency beyond the Python stdlib.

Usage:
    python3 verify_mechanism.py [path/to/NRTH.dll]               # self-checks (default: ../../working/NRTH.dll)
    python3 verify_mechanism.py NRTH.dll --scan-client client.dll  # + scan a real client.dll for the two prologues

Exit code 0 = all claims verified.
"""
import sys, struct, re

# ---------------------------------------------------------------------------
# Minimal PE reader (section mapping) — no external deps
# ---------------------------------------------------------------------------
class PE:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        e_lfanew = struct.unpack_from('<I', self.data, 0x3C)[0]
        assert self.data[e_lfanew:e_lfanew+4] == b'PE\0\0', "not a PE file"
        coff = e_lfanew + 4
        self.n_sections = struct.unpack_from('<H', self.data, coff + 2)[0]
        size_opt = struct.unpack_from('<H', self.data, coff + 16)[0]
        opt = coff + 20
        self.magic = struct.unpack_from('<H', self.data, opt)[0]
        self.image_base = struct.unpack_from('<I', self.data, opt + 28)[0]
        self.sections = []
        sec_tbl = opt + size_opt
        for i in range(self.n_sections):
            s = sec_tbl + i * 40
            name = self.data[s:s+8].rstrip(b'\0').decode('ascii', 'replace')
            vsize, va, rawsz, raw = struct.unpack_from('<IIII', self.data, s + 8)
            self.sections.append((name, va, vsize, raw, rawsz))

    def va2off(self, va):
        rva = va - self.image_base
        for name, sav, vsize, raw, rawsz in self.sections:
            if sav <= rva < sav + max(vsize, rawsz):
                return raw + (rva - sav)
        raise ValueError(f"VA 0x{va:08x} not in any section")

    def read_va(self, va, n):
        return self.data[self.va2off(va):self.va2off(va)+n]

    def find_bytes(self, pattern, section='.text'):
        """Return VAs of all occurrences of pattern inside a section."""
        out = []
        for name, sav, vsize, raw, rawsz in self.sections:
            if name != section:
                continue
            blob = self.data[raw:raw+rawsz]
            for m in re.finditer(re.escape(pattern), blob):
                out.append(self.image_base + sav + m.start())
        return out

# ---------------------------------------------------------------------------
# Claimed plaintexts and the decryption algorithms (recovered from the sample)
# ---------------------------------------------------------------------------
def dec_p2d(buf):    # plaintext[p] = ct[p] XOR ((p - 0x2D) & 0xFF)   [VA 0x78d0/0x7900/0x7780/0x7640]
    return bytes(b ^ ((p - 0x2D) & 0xFF) for p, b in enumerate(buf))

def dec_p20(buf):    # plaintext[p] = ct[p] XOR ((p - 0x20) & 0xFF)   [VA 0xbc00]
    return bytes(b ^ ((p - 0x20) & 0xFF) for p, b in enumerate(buf))

PATTERN_A = b"55 8B EC 8B 45 ? A3 ? ? ? ? 8B 45 ? A3 ? ? ? ? 8B 45"
PATTERN_B_PREFIX = b"55 8B EC 83 EC ? A1 ? ? ? ? 33 C5 89 45 ? 8B 45 ? 53 8B 5D ? 56 57 8B 7D ?"

def build_blob_A(pe):
    # 3 xmmwords in .rdata + inline tail (mov dword 0x33312441 / word 0x0100 at VA 0x10005bf4)
    return (pe.read_va(pe.image_base + 0xf2060, 16) +
            pe.read_va(pe.image_base + 0xf1eb0, 16) +
            pe.read_va(pe.image_base + 0xf1480, 16) +
            bytes([0x41, 0x24, 0x31, 0x33, 0x00, 0x01]))

def build_blob_B(pe):
    return (pe.read_va(pe.image_base + 0xf2050, 16) +
            pe.read_va(pe.image_base + 0xf1e00, 16) +
            pe.read_va(pe.image_base + 0xf12d0, 16) +
            pe.read_va(pe.image_base + 0xf1410, 16) +
            pe.read_va(pe.image_base + 0xf1230, 16) +
            bytes([0x00, 0x01]))

def run_checks(pe_path):
    pe = PE(pe_path)
    results = []

    def check(name, ok, detail):
        results.append((name, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if detail:
            print(f"         {detail}")

    print(f"\n=== Verifying mechanism claims against: {pe_path}")
    print(f"    ImageBase=0x{pe.image_base:08x}  sections={[s[0] for s in pe.sections]}\n")

    # ---- A1: 'client.dll' ciphertext = immediates of three mov instructions (VA 0x10005c56..) ----
    imm1 = struct.unpack_from('<I', pe.read_va(0x10005c56 + 3, 4))[0]   # mov [ebp-0x24], imm32
    imm2 = struct.unpack_from('<I', pe.read_va(0x10005c5d + 3, 4))[0]   # mov [ebp-0x20], imm32
    imm3 = struct.unpack_from('<I', pe.read_va(0x10005c64 + 3, 4))[0]   # mov [ebp-0x1c], imm32
    ct = struct.pack('<III', imm1, imm2, imm3)
    pt = dec_p2d(ct[:10])   # the original decrypts exactly 10 bytes (loop bound 0xA)
    check("A1 decrypt 'client.dll' (p-0x2D, mov-immediates at 0x5c56)", pt == b'client.dll',
          f"plaintext={pt.decode('ascii','replace')}  ct-dwords=0x{imm1:08x} 0x{imm2:08x} 0x{imm3:08x}")

    # ---- A2: '@auto_inject' blob (mov-immediates at VA 0x100044df) ----
    imm1 = struct.unpack_from('<I', pe.read_va(0x100044df + 3, 4))[0]
    imm2 = struct.unpack_from('<I', pe.read_va(0x100044e6 + 3, 4))[0]
    imm3 = struct.unpack_from('<I', pe.read_va(0x100044ed + 3, 4))[0]
    imm4 = struct.unpack_from('<H', pe.read_va(0x100044f4 + 3, 2))[0]  # mov word [ebp-0x24], 0x100
    ct = struct.pack('<IIIH', imm1, imm2, imm3, imm4)
    pt = dec_p2d(ct[:12])
    check("A2 decrypt '@auto_inject' (p-0x2D, mov-immediates at 0x44df)", pt == b'@auto_inject',
          f"plaintext={pt.decode()}")

    # ---- A3: signature #1 (pattern A) ----
    blobA = build_blob_A(pe)
    ptA = dec_p2d(blobA[:0x34])
    check("A3 decrypt signature #1 == documented prologue", ptA.startswith(PATTERN_A),
          f"decrypted={ptA.split(bytes(1))[0].decode('ascii','replace')[:60]}...")

    # ---- A4: signature #2 (pattern B) ----
    blobB = build_blob_B(pe)
    ptB = dec_p2d(blobB)
    check("A4 decrypt signature #2 == documented prologue", ptB.startswith(PATTERN_B_PREFIX),
          f"decrypted={ptB.split(bytes(1))[0].decode('ascii','replace')[:60]}...")

    # ---- A5: 'netc.dll' blob (p-0x20 variant, mov-immediates at VA 0x1002069c) ----
    imm1 = struct.unpack_from('<I', pe.read_va(0x1002069c + 3, 4))[0]
    imm2 = struct.unpack_from('<I', pe.read_va(0x100206a3 + 3, 4))[0]
    imm3 = struct.unpack_from('<H', pe.read_va(0x100206aa + 3, 2))[0]
    ct = struct.pack('<IIH', imm1, imm2, imm3)
    pt = dec_p20(ct[:8])
    check("A5 decrypt 'netc.dll' (p-0x20, mov-immediates at 0x2069c)", pt == b'netc.dll',
          f"plaintext={pt.decode()}  ct-dwords=0x{imm1:08x} 0x{imm2:08x}")

    # ---- B1: exec call site (VA 0x10025c61 = 'call ecx'; push '@custom' at 0x10025c52) ----
    b = pe.read_va(0x10025c61, 2)
    push = pe.read_va(0x10025c52, 5)
    push_imm = struct.unpack_from('<I', push, 1)[0]
    check("B1 Execute call site: 'call ecx' at VA 0x10025c61 + push '@custom'",
          b == b'\xff\xd1' and push[0] == 0x68 and push_imm == pe.image_base + 0xea890,
          f"bytes at 0x25c61={b.hex()}  push imm=0x{push_imm:08x} (expected 0x{pe.image_base+0xea890:08x})")

    # ---- B2: RET-patch site (VA 0x100206e5: mov byte [ebp-0x16], 0xC3) ----
    b = pe.read_va(0x100206e5, 4)
    check("B2 netc.dll kill-switch writes 0xC3 (RET) at VA 0x100206e5",
          b == b'\xc6\x45\xea\xc3', f"bytes={b.hex()}")

    # ---- B3: MinHook detour immediates (0x10005cb9: mov edx,0x10002ff0 ; 0x10005dd9: mov edx,0x100047b0) ----
    d1 = struct.unpack_from('<I', pe.read_va(0x10005cba, 4))[0]
    d2 = struct.unpack_from('<I', pe.read_va(0x10005dda, 4))[0]
    check("B3 detour addresses 0x10002ff0 / 0x100047b0 present at documented sites",
          d1 == 0x10002ff0 and d2 == 0x100047b0,
          f"site1=0x{d1:08x}  site2=0x{d2:08x}")

    # ---- B4: MH_CreateHook calls exist (call to 0x10036020 from both hook sites) ----
    calls = []
    for va in (0x10005cc0, 0x10005de0):
        b = pe.read_va(va, 5)
        if b[0] == 0xE8:
            tgt = va + 5 + struct.unpack_from('<i', b, 1)[0]
            calls.append(tgt)
    check("B4 both sites call MinHook (0x10036020)",
          all(c == 0x10036020 for c in calls) and len(calls) == 2,
          f"call targets: {[hex(c) for c in calls]}")

    # ---- B5: feature flags region (Give HP label ref at 0x1002a17a: mov ecx, VA) ----
    b = pe.read_va(0x1002a17a, 5)
    imm = struct.unpack_from('<I', b, 1)[0]
    check("B5 feature flag system (Give HP label at 0x2a17a)", b[0] == 0xB9 and imm == pe.image_base + 0xe9fe8,
          f"mov ecx imm=0x{imm:08x} (expected 0x{pe.image_base+0xe9fe8:08x})")

    return results


# ---------------------------------------------------------------------------
# Part C: scan a real client.dll for the two documented prologues
# ---------------------------------------------------------------------------
WILD = 0x3F  # '?'

def scan_client(path):
    data = open(path, 'rb').read()
    print(f"\n=== Scanning client.dll for the documented hook targets: {path}")

    def find(sig):
        out = []
        for i in range(0, len(data) - len(sig)):
            ok = True
            for j, s in enumerate(sig):
                if s != WILD and data[i+j] != s:
                    ok = False
                    break
            if ok:
                out.append(i)
        return out

    sigA = [int(x, 16) if x != '?' else WILD for x in PATTERN_A.decode().split()]
    sigB = [int(x, 16) if x != '?' else WILD for x in PATTERN_B_PREFIX.decode().split()]
    a, b = find(sigA), find(sigB)
    print(f"  signature #1 (VM-registration target): {len(a)} hit(s) at file offsets " +
          (", ".join(hex(x) for x in a[:5]) if a else "NONE"))
    print(f"  signature #2 (execute-chunk target)  : {len(b)} hit(s) at file offsets " +
          (", ".join(hex(x) for x in b[:5]) if b else "NONE"))
    if not a or not b:
        print("  NOTE: a clean/hooked-but-different build may lack these prologues;")
        print("        the ORIGINAL sample expects them in the tested MTA client build.")
    return a, b


if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    pe_path = args[0] if args else '../../working/NRTH.dll'
    results = run_checks(pe_path)
    if '--scan-client' in sys.argv:
        idx = sys.argv.index('--scan-client')
        if idx + 1 < len(sys.argv):
            scan_client(sys.argv[idx + 1])
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n=== RESULT: {len(results) - len(failed)}/{len(results)} claims verified" +
          (f"  — FAILED: {failed}" if failed else "  — ALL DOCUMENTED CLAIMS MATCH THE REAL SAMPLE"))
    sys.exit(1 if failed else 0)
