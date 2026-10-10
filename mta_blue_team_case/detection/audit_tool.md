# NRTH_audit — the shipped defensive module (`NRTH_audit.dll` + `nrth_audit.exe`)

Companion to `recovered_strings.txt`. This is the one piece of the reconstruction that is
built and delivered as a working binary, because it is a *detector*, not a capability: it
reads a PE file (or an already-owned memory dump) and answers the two questions the case
actually needs.

1. *Is the cheat's work visible in this module?* — find the client.dll/netc.dll functions by
   the patterns the cheat itself uses, then classify their first bytes: `PRISTINE` or a
   tamper footprint (`E9` near jump, `FF 25` absolute jump, `68 .. C3` trampoline, or the
   single `C3` "check kill" the sample writes).
2. *What did we not see before decoding?* — decode/re-verify the sample's positional-XOR
   records and sweep a `.data`/`.rdata` region for prologue-anchored hidden patterns.

## Files

| Path | What it is |
|---|---|
| `recovered_or_reconstructed_project/src/nrth_audit.h` | API contract, error codes, explicit non-goals |
| `.../src/nrth_audit_sigs.h` | the 20 High-confidence signatures — **generated**, do not hand-edit |
| `.../src/nrth_audit.cpp` | implementation (plain C++17, no OS coupling, no vendor dependency) |
| `.../src/nrth_audit.def` | export names + pinned ordinals 1–21 |
| `.../tools/nrth_audit_cli.cpp` | CLI: `selftest` `signatures` `decode` `sweep` `audit` |
| `.../tools/pe_summary.py` | dependency-free PE header/export verifier used by the build |
| `.../tools/gen_nrth_audit_sigs_h.py` | regenerates the table from `working/sigs.json` |
| `.../tests/test_nrth_audit.cpp` | 27 host unit tests |
| `.../run_all_tests.sh` | one command that re-runs every test claim in this case (8 groups incl. YARA, the sample differentials and the cross-build diff control) |
| `.../tools/pe_deterministic.py` | makes the delivered PE artifacts hash-pinnable (timestamp / CodeView GUID / build id zeroed); run by the build scripts |
| `.../tools/nrth_string_va.py` | verifies any `"<string>" ... 0xADDR` claim in this folder's docs against the packed image (`--find`, `--check`, `--audit-docs`) |
| `.../build_audit.sh` | host tests first, then the PE32 x86 cross build |

Generated artefacts land in `recovered_or_reconstructed_project/bin/`
(`NRTH_audit.dll`, `nrth_audit.exe`, `nrth_audit.lib`) and are git-ignored; the case folder
keeps the build log instead (`../test_results/audit_build.log`).

## Build

```
$ cd recovered_or_reconstructed_project
$ ./build_audit.sh                 # host tests + selftest, then zig cross-build (PE32 x86)
$ ./build_audit.sh --host          # host binaries only
$ ./build_audit.sh --regen         # re-derive src/nrth_audit_sigs.h from working/sigs.json first
```

No `fetch_vendor.sh` step is needed: the module deliberately does not use MinHook, ImGui or
Lua, so the delivered DLL is a single translation unit plus a generated table — reviewable
in one sitting.

Last verified run (2026-10-10, Linux host, g++ 12.2 + ziglang 0.17.0):

```
[*] 30/30 checks passed                       # unit tests
result: all checks passed                     # NrthAuditSelfTest: 21 checks, all sample-derived
$ ./run_all_tests.sh
=== summary: 9 passed, 0 failed, 0 skipped (a clone without bin/ gives 8 passed + 1 skipped)        # incl. the YARA check and both sample differentials
[+] Built:
  bin/NRTH_audit.dll   293,376 B  sha256 c13167666a0a3e16ed870e7b74871410eb848063d71a7682c6773b40e408fe9f
  bin/nrth_audit.exe   304,640 B  sha256 1c24702ac10df6fc1f07cd74f193d36f1aa3ffc7ae9c343881d9ebe6b3fcdf0a
     (reproducibility: zig's lld keeps a wall-clock PE TimeDateStamp, so rebuilding the same
      sources yields a different DLL hash — compare size/exports, and re-read these from a log)
  machine 0x014c IMAGE_FILE_MACHINE_I386, magic 0x10b (PE32), image base 0x10000000,
  DYNAMICBASE + NX_COMPAT, 23 exports (ordinal 1 = NrthAuditVersion ... 21 = NrthAuditSelfTest,
  22 = NrthAuditDiff, 23 = NrthAuditDiffFiles)
```

The architecture matches the original `NRTH.dll` (PE32 x86, same preferred image base), which
matters because the patterns are 32-bit x86 code.

## Using it on an endpoint

```
nrth_audit.exe audit   C:\...\MTA San Andreas\mods\deathmatch\client.dll
nrth_audit.exe audit   C:\...\mods\deathmatch\netc.dll  --csv netc.csv
nrth_audit.exe diff    C:\baseline\client.dll  C:\dumps\client-from-suspect.dll   # A/B (see below)
nrth_audit.exe sweep   <suspicious-module> --min 24
nrth_audit.exe decode  <module> --rva 0x13bd10 --len 156
nrth_audit.exe selftest
```

Exit codes: `0` clean · `1` bad argument / self-test failure · `2` input unreadable or not a
PE image · `3` at least one tamper footprint found. `3` is what an EDR custom check keys on;
`--csv` gives one row per signature for a collector.

### The A/B diff: what counts as tampering (1.2.0)

`diff <baseline> <compared>` audits both images with the same 20-row catalogue and then compares
**per signature**, not per byte. The rule that makes it usable:

> A footprint counts only when the compared image carries it **on the function the baseline located
> at that same RVA**. Everything else is `sus_unlocated` — shown, never alerted on.

That rule came from a measurement against our own repository: diffing the original `NRTH.dll`
(baseline) against this project's reconstruction (a different build of a similar module) produced
`[18] 0/0 -> 0/1 DETOUR_JMP32 @0x0d9f91` — a jump thunk in *our* binary that happens to match a
`client.dll` pattern. Alerting on that would flood any build comparison, so 1.2.0's looser rule was
replaced; the same run now reports `verdict: 0` plus one informational row, and `run_all_tests.sh`
group 5 keeps it as a regression test.

Row semantics (`--csv` columns with the same names):

| field | meaning | act on it? |
|---|---|---|
| `clean_full/clean_patched` | hits in the known-good baseline (intact / carrying a footprint) | context |
| `sus_full/sus_patched` | hits in the loaded or dumped copy | context |
| `added_footprint` | baseline located the function intact, compared copy has a footprint there | **yes — this is the alert**, and it is the function's return value |
| `target_lost` | baseline found the pattern, compared copy did not | no: usually another MTA build ⇒ re-baseline |
| `sus_unlocated` | a footprint at an RVA the baseline never located | no: another build / unrelated code |

Return value = number of `added_footprint` rows (CLI exit `3` when non-zero). Because alignment is
by located RVA, the two files do not need the same image base — but a meaningful verdict still needs
the same build; `target_lost` / `sus_unlocated` are what differing builds turn into, by design.

Run it against a **dump you are allowed to read** when you want live evidence: a MinHook
detour and a `0xC3` kill are written into memory, not into the file on disk, so an on-disk
`client.dll` will normally report `PRISTINE` even on a compromised client. On-disk
tampering is still detected.

Embedding it (`LoadLibrary` + `GetProcAddress`, or link `nrth_audit.lib`): the whole API is
`extern "C"`, takes `const uint8_t *` + `size`, and never writes to the input buffer.

## What the catalogue covers, and what it does not

- **20 rows compiled in** — the High-confidence signatures, each recovered from a decryptor
  record in the sample, tagged with the decryptor VA, the XOR key, the owner function that
  installs it and the target module (7 from the hook installer at `0x10005b80`, 12 from
  `0x1000c390`, 1 from the `netc.dll` cluster starting at `0x10020640`).
- **8 more are evidence, not compiled in** — the Medium-confidence `.data` candidates
  (`recovered_strings.txt` Section C.2). They over-read past the record boundary, so they are
  documented as candidates only.
- **Module-relative, not absolute**: the patterns locate functions inside *their* module. A
  patched/rebuilt `client.dll` changes which RVA comes back, which is exactly the signal.
- The 6 `0xC3` write sites (0x100206f0, 0x100208aa, 0x10020927, 0x10020f46, 0x100214bd,
  0x100215f1) take their target patterns from `.data` globals at *run time*, so the identity
  of the six disabled netc.dll functions stays **Unknown** without a runtime dump. The tool
  can find and check them; it cannot name them from static bytes.

## Why the patched check is strict (measured, not assumed)

A natural first implementation — wildcard the first token of the signature and match the tail
— produced **5 false positives out of 20 rows when run against `NRTH.dll` itself**: real,
untouched MSVC prologues elsewhere in code collide with a tail-only match. The audit therefore
substitutes a *concrete* footprint over the function entry instead:

```
C3                ← the sample's one-byte check kill (writer 0x10011870: VirtualProtect 0x40 + 1-byte copy)
E9 ? ? ? ?        ← MinHook near detour (5 bytes)
FF 25 ? ? ? ?     ← absolute jump through memory (6 bytes)
68 ? ? ? ? C3     ← push-addr/ret trampoline form (5 bytes)
```

and additionally requires `NrthPrologueIsTamper()` to accept the state. Result: `0 with a
match` on both sample files (`NRTH.dll`, `NORTH LOADER.exe`) — a clean verdict on a benign
image, which is the property a detection needs. `NrthPatWidenHead()` (the wildcard form) is
still exported for hand-written rules, with its noise documented.

## Scope, honestly stated

The module does not implement, and this repository will not ship, the two mechanisms people
usually ask for when they see this sample: taking over the game's live Lua VM `exec` path, and
disabling netc.dll's integrity checks. Those are the cheat itself — running them requires code
injection into another process, and their effect is a working cheat. Everything needed for
*detection and triage* of them is here instead (the exact strings, keys, resolvers, patterns,
hook inventory, patch primitive and write sites), which is also what makes the case reusable in
an EDR rule or a private-server test. `src/nrth_audit.h` carries the same note as "non-goals"
so the boundary travels with the code.
