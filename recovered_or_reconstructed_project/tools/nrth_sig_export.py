#!/usr/bin/env python3
"""nrth_sig_export.py — export the NORTH/NVX sample's hook-target signature catalogue.

Two complementary, fully static extraction passes:

 1. CODE-RECORDED pass (`nrth_strings_recover.recover`): every obfuscated record the
    program builds on the stack / in place and decrypts with one of its per-length
    one-shot decryptors. Exact, low noise, but only sees records built that way.
 2. DATA-SWEEP pass: scan every 4-byte-aligned position of every section, try all 256
    positional-XOR keys, and keep runs that *start with a compiler function prologue*
    ("55 8B EC" / "53 8B DC") and are >= 20 chars. This catches signature strings held
    in .data/.rdata records that pass 1 cannot reassemble. The prologue anchor is what
    keeps noise out (an arbitrary key on random bytes does not spell a prologue).

Output: JSON, one entry per distinct signature with the evidence location and which
pass(es) found it. Consumed by src/nrth_audit_sigs.h (generated) and by the case docs,
so the detection table and the analysis never drift apart.

Read-only; requires pefile + capstone.
Usage: python3 nrth_sig_export.py <NRTH.dll> <out.json>
"""
import json
import re
import sys

import pefile

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from nrth_strings_recover import Image, recover, decode, func_bounds  # noqa: E402

PROLOGUES = ("55 8B EC", "53 8B DC")
SIG_RE = re.compile(r"^(?:[0-9A-F]{2} |\? ){3,}[0-9A-F? ]*$")


def sweep(img):
    """Anchor-based sweep: only positions whose decode *begins* with a compiler function
    prologue are considered, which pins the key in one step (no 256-key brute force) and
    keeps random-byte noise out.  plain[0] = cipher[0] ^ ((0 - K) & 0xFF)  =>
    K = -(cipher[0] ^ '5') & 0xFF, then verify the rest of the prologue."""
    pe, base = img.pe, img.pe.OPTIONAL_HEADER.ImageBase
    out = {}
    prefixes = [b"55 8B EC ", b"53 8B DC "]
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode(errors="replace")
        if name not in (".data", ".rdata", ".text"):
            continue
        data = bytes(sec.get_data())
        n = len(data)
        for start in range(0, n - 12, 4):
            for pref in prefixes:
                key = (-(data[start] ^ pref[0])) & 0xFF
                head = bytes(data[start + i] ^ ((i - key) & 0xFF) for i in range(len(pref)))
                if head != pref:
                    continue
                txt = bytearray()
                i = len(pref)
                while i < 1024 and start + i < n:
                    c = data[start + i] ^ ((i - key) & 0xFF)
                    if c == 0 or not (32 <= c < 127):
                        break
                    txt.append(c)
                    i += 1
                s = (pref + bytes(txt)).decode("ascii")
                if len(s) >= 20 and SIG_RE.match(s):
                    out.setdefault(s, set()).add((name, base + sec.VirtualAddress + start, key))
    return out


def main(dll, outjson):
    img = Image(dll)
    entries = {}

    _decs, records = recover(img)
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    ins = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(img.code(), img.va0()))
    for r in records:
        t = r["text"]
        if t.startswith(PROLOGUES) and SIG_RE.match(t) and len(t) >= 20:
            e = entries.setdefault(t, {"pattern": t, "len": len(t), "passes": set(),
                                       "code_sites": set(), "data_sites": set(), "owner": None, "module": None,
                                       "key": "0x%02X" % (r["key"] or 0),
                                       "decryptor": "0x%08x" % r["decryptor"]})
            e["passes"].add("code-record")
            e["code_sites"].add("0x%08x" % r["site"])
            f0, _f1 = func_bounds(ins, r["site"])
            e["owner"] = "0x%08x" % f0 if f0 else "?"
            # module name record nearest before the site inside the same function
            mod = None
            for q in records:
                if q["text"].endswith(".dll") and f0 and f0 <= q["site"] < (_f1 or 0):
                    mod = q["text"]
            e["module"] = mod

    for s, locs in sweep(img).items():
        e = entries.setdefault(s, {"pattern": s, "len": len(s), "passes": set(),
                                   "code_sites": set(), "data_sites": set(),
                                   "key": "-", "decryptor": "-", "owner": "-", "module": None})
        e["passes"].add("data-sweep")
        for nm, va, key in sorted(locs):
            e["data_sites"].add("%s@0x%08x" % (nm, va))
        e["key"] = "0x%02X" % sorted(k for _, _, k in locs)[0]

    # drop entries that are a strict prefix of a longer one (record truncated by a
    # window boundary rather than being a distinct signature)
    allpats = list(entries)
    for t in list(entries):
        if any(o != t and o.startswith(t) for o in allpats):
            del entries[t]
    ordered = sorted(entries.values(), key=lambda x: (-x["len"], x["pattern"]))
    payload = {
        "sample": dll,
        "image_base": "0x%08x" % img.pe.OPTIONAL_HEADER.ImageBase,
        "codec": "plain[p] = cipher[p] XOR ((p - key) & 0xFF); one-shot flag byte at record+L+1",
        "signatures": [{
            "id": n + 1,
            "pattern": e["pattern"],
            "len": e["len"],
            "passes": sorted(e["passes"]),
            "code_sites": sorted(e["code_sites"]),
            "data_sites": sorted(e["data_sites"]),
            "xor_key": e["key"],
            "decryptor": e["decryptor"],
            "owner_func": e.get("owner"), "module": e.get("module"),
            # Confidence: both passes agree (or a code-record site exists) -> High; data-sweep
            # only -> Medium (string is coherent and anchored on a prologue, but the owning
            # call site was not reassembled).
            "confidence": "High" if e["code_sites"] else "Medium",
        } for n, e in enumerate(ordered)],
    }
    with open(outjson, "w") as f:
        json.dump(payload, f, indent=2)
    hi = sum(1 for s in payload["signatures"] if s["confidence"] == "High")
    print("[+] %d signature(s) -> %s   (%d High / %d Medium)"
          % (len(payload["signatures"]), outjson, hi, len(payload["signatures"]) - hi))
    for s in payload["signatures"]:
        print("  [%2d] %s  len=%-3d %s  %s" % (s["id"], s["confidence"][:1], s["len"],
                                               ",".join(s["passes"]), repr(s["pattern"][:70])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
