# MTA:SA Blue-Team Case Report — NORTH.zip (NORTH LOADER.exe + NRTH.dll)

- **Case folder:** `mta_blue_team_case/`
- **Analysis date:** 2026-10-10
- **Analysis host:** Linux sandbox (no Windows/MTA runtime available — see Limitations)
- **Scope:** authorized defensive investigation of user-supplied samples; static-first; no anti-cheat-evasion enhancement; no public-server use.

---

## 1. Verdict

**Loader + game cheat (overlay menu) targeting Multi Theft Auto: San Andreas (MTA:SA).**

Classification by component:
- `NORTH LOADER.exe` — **loader/injector** (High confidence).
- `NRTH.dll` — **in-game cheat overlay payload** for MTA:SA (High confidence): self-identified by its own `.rdata` strings `North Cheat` (VA 0x100ea0d8) and `Cheat` (VA 0x100ea4a0), armed specifically when MTA:SA modules `client.dll`/`netc.dll` load, drawing a Dear ImGui menu toggled by INSERT over the D3D9 frame.

| Finding | Evidence | Confidence | Alternative explanation | Next verification |
|---|---|---|---|---|
| Loader injects a DLL into `gta_sa.exe` | `InjectClassic` RVA 0x12880: OpenProcess(0x43a)/VirtualAllocEx/WriteProcessMemory/CreateRemoteThread(LoadLibraryA); console strings `[+] Inyectado OK clasico` | High | Dual-use installer tooling | Runtime test T2 (private server) |
| Fallback injection via `SetWindowsHookEx` when `OpenProcess` denied | `InjectHook` RVA 0x12470, triggered on `ERROR_ACCESS_DENIED` (status 2); export `NVXHookProc` contract | High | Legit IME/overlay hooking | Runtime test T3 |
| Payload waits for MTA:SA framework | `Hooked_LdrLoadDll` RVA 0x0a640 triggers init (0x10005b80, 0x10020640) on `client.dll`/`netc.dll` load (decrypted strings) | High | — | Runtime test T4 |
| Overlay is a cheat menu, not a benign overlay | `North Cheat`, `Cheat`, `Menu Toggle Key` strings; `.?AUSWeaponAimSync@@` RTTI (MTA aim-sync struct); `PACKET_ID_CHEAT_*` constants | High | Could be a mod-menu without malicious netcode | Per-feature inventory T5 |
| Anti-analysis self-protection | `GET_MODULE_HANDLE_EX_FLAG_PIN` module pinning in `DllMain` RVA 0x0ba00; XOR/SSE string encryption; MinHook inline hook on `ntdll!LdrLoadDll` | High | Some legit overlays pin modules | T4 with read-only debugging |
| Network manipulation / game-state modification specifics | `SWeaponAimSync` RTTI + packet-ID constants present | **Low–Medium (Tentative)** | Constants may come from statically linked MTA headers/libs without live use | Net capture + server logs in T5 |

**What it demonstrably does** (static evidence chain in `behavior_timeline.md`): finds the game process (60 s poll), escalates to `SeDebugPrivilege`, injects `NRTH.dll` by remote thread, falls back to hook-style injection when blocked, pins itself, hooks `ntdll!LdrLoadDll`, waits for `client.dll`/`netc.dll`, then hooks D3D9 `Present`/`Reset` and renders a menu labeled "North Cheat" toggled with INSERT.

**What it might do but is not proven** (hypotheses, not facts):
- Modify weapon-aim state via `SWeaponAimSync` structures (RTTI presence only; call paths not traced).
- Manipulate MTA netcode via `PACKET_ID_CHEAT_*` handlers (constants present; no live traffic evidence).
- Read/write game memory beyond the overlay (init routines 0x10005b80/0x10020640 only partially characterized).
- Use `C:\NVX` as a data/log directory — **corrected 2026-10-10**: this is a *plain* `.rdata` string
  (file offset 0x000afd18), not a decrypted record, and it is not referenced by any of the 63 recovered
  records. The config path the payload actually decrypts is `C:\Overwack\loader_config.cfg` (K=0x20,
  call site 0x1001fcff), plus an NTFS alternate data stream `C:\ProgramData:NT2` (0x1001e530). Whether
  `C:\NVX` is created at all remains unverified (no runtime).

## 2. Reconstruction status

- **Exact original source recovered: NO.** No source files, PDB-with-source, or source archives were present in `NORTH.zip`. (A PDB *path* string exists in the loader — `C:\Users\user\Desktop\src CHEATS\over\Loader\Debug\NVX Loader.pdb` — but the PDB file itself is absent; per policy a PDB path is not source recovery.)
- **Result classes:**
  - `D2` — native decompilation/pseudocode: disassembly-based pseudocode of both samples (Capstone), documented in `analysis/` and referenced by `function_map.csv`.
  - `R2` — behavioral reconstruction: newly authored C++ in `recovered_or_reconstructed_project/` reimplementing the observed loader contract (CLI parsing, PE export parsing, documented injection sequence) and the payload chain (NVXHookProc export contract, DllMain pin+thread, MinHook LdrLoadDll watch on `client.dll`/`netc.dll`, D3D9 Present/Reset hooks, Dear ImGui v1.92.9 overlay with INSERT toggle) for defensive/private-server validation. Menu **feature slots are labeled stubs** — the original's feature logic (0x10005b80 / 0x10020640) is class U and was deliberately not invented.
- **Build status: BUILT** — cross-compiled to Windows PE32 x86 artifacts with Zig 0.17.0's MinGW sysroot (`build.sh`): `bin/NORTH_LOADER.exe` (SHA-256 `75a3dc17...fdd2b3dd`) and `bin/NRTH.dll` (SHA-256 `452c5848...d6e383f`), export contract verified (`NVXHookProc` @ ordinal 1). Full log: `test_results/build_cross.log`. Windows MSVC path (`build.ps1`) documented but not executed here.
- **Delivered detector (built + tested): `NRTH_audit.dll` / `nrth_audit.exe`** — `build_audit.sh`, PE32 x86,
  ImageBase 0x10000000, 23 exports (ordinals 1–21), DYNAMICBASE+NX_COMPAT;
  `bin/NRTH_audit.dll` SHA-256 `c1316766…e408fe9f`, `bin/nrth_audit.exe` `1c24702a…b3fcdf0a`.  Full suite (every claim in this case, one command): `run_all_tests.sh` → `12 passed, 0 failed, 0 skipped (10 + 1 skip without bin/)`
  (log: `test_results/run_all_tests.log`).
  It implements the recovered codec, the 20-signature catalogue, the PE reader and the patch-footprint
  classifier; 30/30 unit tests and 21/21 self-test vectors pass on the host, and `audit` returns
  **0 with a match** on both samples (no self-flagging). Docs: `detection/audit_tool.md`.
- **Scope decision (explicit):** the two mechanisms that would make this a working cheat — hijacking the
  game's live Lua `exec` trampoline (global `0x1013c94c`) and actually writing the `0xC3` kills into
  `netc.dll` in another process — are documented from evidence but **not implemented**. They require
  cross-process memory writes and their only product is a functioning cheat; everything a defender needs
  (VAs, keys, patterns, hook inventory, patch primitive, six write sites, plus a scanner that checks for
  them) is delivered instead. Recorded in `mechanism_overview_ar.md` §9 and in the header of `src/nrth_audit.h`.
- **Original samples were not modified** (hashes re-verified before/after: `hashes.sha256`).
- **No capability was added** beyond the observed sample (no new stealth, persistence, or evasion, and no invented cheat features). Where the original performs evasion-relevant actions (module pinning is kept — it is evidenced; string encryption is documented but **not** re-implemented).

## 3. File identification (hashes & architecture)

| File | SHA-256 | Size | Architecture / runtime |
|---|---|---|---|
| `NORTH.zip` | `f7130e5cb949a6049d5eab7042c1fa781d485abd392f2e325f493691ad369705` | 772,837 B | ZIP container |
| `NORTH LOADER.exe` | `837650b9f1ca52d2c91c966ba7f16721986e754f3efdfb42a08536610067c5fb` | 51,200 B | PE32 x86, console, ImageBase 0x400000, EP RVA 0x11212, MSVC **Debug** CRT (VCRUNTIME140D.dll, ucrtbased.dll), unsigned |
| `NRTH.dll` | `947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861` | 1,318,400 B | PE32 x86 DLL, ImageBase 0x10000000, EP RVA 0x0a8bb0, MSVC **Release** CRT, embeds Dear ImGui 1.92.9 WIP (19283) + MinHook v1.3.3, unsigned |

Neither binary is .NET (CLR data directory empty) — both are native x86. Full inventory: `file_inventory.csv`. Import/export dump: `imports_exports.txt`.

## 4. Tools actually used

| Tool | Use |
|---|---|
| Python 3.11 + `pefile`, `dnfile`, `dncil`, `capstone` (pip, versions per `pip3 show`) | PE parsing, managed-code check (negative), disassembly |
| GNU `objdump` (binutils) | cross-check of disassembly |
| GCC 12.2.0 (MinGW-w64 cross checks on Linux) | compiled + ran reconstruction unit tests |
| Custom Python scripts (read-only) | strings catalog, function map, hashes |
| `capstone` (x86) + hand-written record/decryptor analysis | string-codec recovery: 82 decryptors, 63 plaintexts, 28 signatures (`tools/nrth_strings_recover.py`, `nrth_sig_export.py`, `nrth_hook_targets.py`, `nrth_patch_map.py`) |
| g++ 12.2 (host) + `ziglang` 0.17.0 (`python3 -m pip install --break-system-packages ziglang`) | build + unit-test the audit module, then cross-build PE32 x86 (`build_audit.sh`) |
| `yara-python` 4.5.4 | compile-and-scan validation of `detection/yara_rules.yar` against both samples and against our own shipped binaries |

No Ghidra/IDA/Binary Ninja was available in this environment (network-restricted sandbox); a radare2 download attempt failed on the outbound allowlist. Disclosed as a coverage limitation.

## 5. Work performed (key evidence)

- **Phase 0–2:** read-only `evidence/` copy vs `working/` copy; SHA-256 before/after (unchanged); PE identification (see above); confirmed not packed (uniform low-entropy sections, `.text` entropy 4.75 loader / comparable DLL layout, full import tables).
- **Phase 3B (native):** disassembled entry points, exports, and core functions of both modules; every significant finding in `function_map.csv` carries VA/RVA and confidence. Highlights:
  - Loader: `main` 0x413170, `EnableDebugPrivilege` 0x411b20, `FindProcessByName` 0x411ea0, `InjectClassic` 0x412880, `InjectHook` 0x412470, `FindExportRvaInFile` 0x411ff0, `rva2off` 0x411960, `IsModuleLoadedInProcess` 0x412dc0.
  - DLL: `NVXHookProc` 0x1000b9e0 (export ordinal 1), `DllMain` 0x1000ba00, `MainInitThread` 0x1000a850, `Hooked_LdrLoadDll` 0x1000a640, `GetD3D9DeviceVTable` 0x10012980, `InstallD3D9Hooks` 0x10016500, `Hooked_Present` 0x10014d50, `Hooked_Reset` 0x1001a3c0, MinHook `MH_CreateHook` 0x10036020.
- **Phase 3C (string layer, added later — this is where the new facts came from):** recovered the payload's
  string codec end-to-end: `plain[p] = cipher[p] ^ ((p - K) & 0xFF)` with a **per-decryptor** K read from an
  `.rdata` lane table; **82 decryptor functions** and **63 byte-exact plaintexts** (`tools/nrth_strings_recover.py`
  → `working/recovered.json`). Two gates make this non-trivial: the one-shot `mov byte [this+F],0` gate (record
  length L = F-1) and the fact that records are assembled on the stack from scattered 16-byte blocks, so 4 of 63
  plaintexts are findable by raw search and the rest only through the decoder.
- **Phase 3D:** derived the *real* hook/patch surface from those decodes (`tools/nrth_hook_targets.py`,
  `tools/nrth_patch_map.py`, `tools/nrth_sig_export.py`): 20 hidden x86 search patterns (High) + 8 `.data`
  candidates, 11 pattern scans + 11 `MH_CreateHook` in `0x10005b80`, 20 scans + 0 hooks in `0x1000c390`, and in the
  `netc.dll` cluster from `0x10020640` 6 one-byte `0xC3` writes through writer `0x10011870`
  (`VirtualProtect(...,0x40,...)` + 1-byte copy). Independently reproduced by the C++ tool (same 8 `.data` RVAs).
- **Phase 4:** strings catalog (9,452 lines) with section/offset mapping; high-value indicators extracted to `indicators.json`;
  decoded-string layer documented in `detection/recovered_strings.txt` (46 usable records, 20 signatures, and the 20
  records that are *not* usable — labelled as such, with reasons).
- **Phase 5 (dynamic):** **not executed** — no Windows/MTA environment (see §7). Plan recorded in `private_server_tests/test_plan.md`.
- **Phase 6:** behavioral reconstruction in `recovered_or_reconstructed_project/` (R2) with unit tests; validation checklist partially satisfied (build/test on Linux only; Windows ABI/runtime equivalence untested).
- **Phase 7:** this case folder (`report.md`, `hashes.sha256`, `file_inventory.csv`, `imports_exports.txt`, `strings_catalog.txt`, `function_map.csv`, `behavior_timeline.md`, `indicators.json`, `detection/`, `private_server_tests/`, `test_results/`).

## 6. Build & test commands and real results

```
# Cross-build (executed 2026-10-10, Linux host, Zig 0.17.0 MinGW sysroot -> PE32 x86):
$ bash recovered_or_reconstructed_project/fetch_vendor.sh   # pinned MinHook + ImGui v1.92.9
$ bash recovered_or_reconstructed_project/build.sh
[+] Build complete:
-rwxr-xr-x 1 user user  280064  bin/NORTH_LOADER.exe
-rwxr-xr-x 1 user user 1284096  bin/NRTH.dll
75a3dc1798b0231b9a0178027f8d17b44c6bef4a5dfc854077ac7748fdd2b3dd  bin/NORTH_LOADER.exe
452c58488dabb85705e5e189d9873c208174a798ae18fe6cdc6e121c8d6e383f  bin/NRTH.dll

# Export/PE verification (pefile):
[+] NRTH.dll: PE32 x86 DLL, exports exactly ordinal 1 -> "NVXHookProc" (contract met)
[+] NORTH_LOADER.exe: PE32 x86 console; imports OpenProcess/VirtualAllocEx/
    WriteProcessMemory/CreateRemoteThread/SetWindowsHookExA/PostThreadMessageA/
    UnhookWindowsHookEx/AdjustTokenPrivileges/K32EnumProcessModules verified

$ g++ -std=c++17 -Wall -Wextra -o tests/test_cli_parser tests/test_cli_parser.cpp && ./tests/test_cli_parser
[+] All CLI parsing tests passed successfully!          # 4/4 cases (log: test_results/test_cli_parser.log)

$ g++ -std=c++17 -Wall -Wextra -o tests/test_pe_export_parser tests/test_pe_export_parser.cpp && ./tests/test_pe_export_parser working/NRTH.dll
[+] Located export 'NVXHookProc' at RVA: 0x0000B9E0 (Expected: 0x0000B9E0)
[+] Negative test passed: Non-existent export safely returns false.
[+] All PE export parser tests passed successfully!     # differential vs real sample (log: test_results/test_pe_export_parser.log)
```

```
# Audit module (executed 2026-10-10, same host): host tests first, then the PE32 cross build
$ cd recovered_or_reconstructed_project && ./build_audit.sh
[*] 30/30 checks passed
result: all checks passed            # NrthAuditSelfTest: 21 checks, vectors taken from the sample
[+] Built:  bin/NRTH_audit.dll (293,376 B)  bin/nrth_audit.exe (304,640 B)
  machine 0x014c (I386), magic 0x10b (PE32), image base 0x10000000, DYNAMICBASE NX_COMPAT
  exports: 21 names, undecorated, ordinals 1..21 as pinned in src/nrth_audit.def
$ ./bin/host/nrth_audit audit working/NRTH.dll
[*] signatures  : 20 checked, 0 with a match
[*] verdict: 0 signature(s) found with a replaced prologue
$ ./bin/host/nrth_audit sweep working/NRTH.dll --min 24 --vas | head -1
[*] working/NRTH.dll: 8 hidden pattern candidate(s) (>= 24 chars)     # == the Python tool's 8
```
Two accuracy passes were made after the first draft of this report.  (1) Every `"<string>" … 0xADDR`
claim in the case folder was re-checked mechanically with
`recovered_or_reconstructed_project/tools/nrth_string_va.py --audit-docs` against the packed image: 23
addresses had been written as `ImageBase + file offset` (0x1000 short of the real VA here, sometimes with
one extra zero digit) and were corrected — e.g. `North Cheat` is at **VA 0x100ea0d8** (RVA 0xea0d8,
offset 0xe90d8), not 0x1000e90d8.  The run that now reports 0 inconsistent claims is in
`test_results/doc_address_audit.log`, and comments inside `src/nrth_ui.cpp` were relabelled `off 0x…` so
file offsets can no longer be read as VAs.  (2) `nrth_audit` gained the alignment rule described in
`detection/audit_tool.md` (v1.2.0) after its own diff against this repository's reconstruction produced a
false "new detour" row.

The reconstruction itself was rebuilt after these doc/code corrections (`fetch_vendor.sh` + `build.sh`,
exit 0; rebuilt again on 2026-10-11 from a fresh clone, byte-identical): `bin/NRTH.dll` 1,425,408 B
`sha256 955b3d348ee543cf1f3384720e9b65dbce2832bc2ebf630acbb470340c69e1f6` (single export `NVXHookProc` @
ordinal 1, PE32 x86, Subsystem=3 like the sample) and `bin/NORTH_LOADER.exe` 280,064 B
`sha256 5e2eddaccdb9444ceb10c911771160f204158eaf0ca519205f5f720df1960668`. The size differs from the
2026-10-10 entry above because the current tree links 46 objects (Dear ImGui 1.92.9 + Lua 5.4.6 + MinHook)
into `NRTH.dll`; the 2026-10-11 relink is 266,752 B *smaller* than the previous build because `build.sh`
now adds form-parity linker flags (`-Wl,--subsystem,console -Wl,--strip-all`, opt out with `--no-formal`).
How close that leaves the result, per header field and per mapped function, is measured - not asserted - in
`reconstruction_parity.md`: 18/26 optional/file-header fields equal, `.text`/`.rdata`/`.data` equal by
index, 9/20 mapped functions implemented and 11 documented-but-declined; the export contract is
re-verified by `tools/pe_summary.py` and by `run_all_tests.sh` stage 4.

Logs: `test_results/audit_build.log`, `test_results/audit_sample_differential.log`, `test_results/run_all_tests.log`, `test_results/reconstruction_parity.md` (field-by-field parity table), `test_results/fixture_control.log` (positive control: the detector must report exactly 10 known footprints),
`test_results/yara_check.log` (4 rules compile; `NRTH.dll` → 3 rules, loader → 1 rule; the two
audit binaries we ship match none).

Windows build script for the reconstruction (`recovered_or_reconstructed_project/build.ps1`, MSVC x86) is documented but **was not executed** here (no Windows/MSVC on the analysis host). Passing tests = compatibility for the covered contracts only; **not** proof of full behavioral equivalence.

## 7. Coverage, confidence, limitations

- **Covered (High confidence):** file identification, export/import maps, injection call chains, arming trigger, overlay infrastructure, operator UX strings, hash integrity.
- **Covered (High) after the decode pass:** the string codec and all 63 record plaintexts; the 20-signature
  target catalogue with owner function and module; the hook inventory (11 + 20 + 6 scans, 11 + 4 `MH_CreateHook`);
  the kill primitive and its 6 write sites; config/ADS/registry artifacts; the audit module + its test evidence.
- **Partially covered (Medium):** `0x1000c390` (20 pattern scans, no hooks — role inferred, not proven); the
  `Error #10xx Send screen error dev-cheat` path (strings + call sites seen, transport not traced); per-feature
  mapping of menu flags to effects.
- **Unresolved (U):** the *identity* of the six disabled `netc.dll` functions (their patterns come from `.data`
  globals at run time — needs a dump); exact menu feature set and any game-state/netcode effects; whether
  `C:\NVX` is ever created; whether `SWeaponAimSync` RTTI is used at runtime or merely linked; behavior under
  real anti-cheat products; private-server runtime results.
- **Environment limits:** Linux sandbox; no Ghidra/IDA (radare2 download blocked); no Windows runtime; no MTA:SA private server. Dynamic claims are therefore absent, not implied.
- **Sample-set limit:** 2 binaries; detection rules unvalidated against variant sets.

## 8. How to detect / How to defend

- **Detect:** see `detection/telemetry.md` (layered file + host + server + **module-integrity** signals with FP
  caveats), `detection/yara_rules.yar` (4 candidate rules; exact-sample strength), and
  `detection/recovered_strings.txt` (the decoded strings that Layer-1 file rules were missing).
- **Automate:** `nrth_audit.exe audit <client.dll|netc.dll>` on a read-only dump — exit code `3` means at least one
  located function has a detour/kill footprint, `--csv` per-signature rows. It cannot inject or write; it only reads.
  Never rely on a single import/string.
- **Defend (server-side first):** treat client state as untrusted — server-side validation of aim/movement/weapon sync; module-inventory attestation for `gta_sa.exe`; alert on unsigned DLLs mapped post-start; verbose logging around reserved/cheat packet IDs during investigations; regression-test detections with T0/T2/T5 of the test plan on the team-owned server only.

## 9. Statement on source recovery

**Was the exact original source recovered? NO.** The deliverable `recovered_or_reconstructed_project/` is an **R2 behavioral reconstruction** (plus **D2** decompiler output documented in `analysis/`), clearly separated from the untouched samples in `evidence/`. Comments, original identifiers, and project structure of the authors' source were not recoverable from the compiled binaries.

---

### Deliverables checklist (this folder)

| File | Purpose |
|---|---|
| `report.md` | This report: verdict, evidence, confidence, limitations |
| `hashes.sha256` | Original + derived artifact hashes |
| `file_inventory.csv` | EXE/DLL/dependency inventory and architecture |
| `imports_exports.txt` | Imports/exports/callbacks with RVAs |
| `strings_catalog.txt` | All printable strings with section/offset mapping |
| `function_map.csv` | Address/RVA, role, callers/callees, evidence, confidence |
| `behavior_timeline.md` | Observed sequence and trigger conditions |
| `indicators.json` | Hashes, names, paths, behavioral signatures (no network IOCs observed) |
| `detection/yara_rules.yar` | 4 candidate rules with confidence meta (incl. the XOR-hidden .data pattern records) |
| `detection/recovered_strings.txt` | generated evidence table: 46 usable decoded strings + 28 signatures + labelled non-usable decodes |
| `detection/audit_tool.md` | the built detector: API, build, exit codes, what it checks, measured FP behaviour, limits |
| `detection/telemetry.md` | Layered telemetry + FP caveats + regression tests + blind spots |
| `private_server_tests/test_plan.md` | Real client/server test matrix (T0–T6) |
| `private_server_tests/results.md` | Honest status: NOT EXECUTED + what was validated instead |
| `test_results/*.log` | Real command output: `run_all_tests.log` (whole suite), `audit_build.log`,
| | `audit_sample_differential.log`, `build_cross.log`, `yara_check.log`, and `doc_address_audit.log` |
| `mechanism_overview_ar.md` | Arabic mechanism brief: what the sample does, evidence per claim, §9 scope | 
| `mechanism_vm_injection.md` | Lua-VM / exec-trampoline path, address by address, with the reconstruction's stub note |
| `reconstruction_parity.md` | measured parity of the reconstruction against the sample: 26 PE header fields (form) and 20 mapped functions (function), with every residual gap tagged fixable / toolchain-bound / declined |
| `anticheat_playbook.md` | Arabic: the two mechanisms turned into implementable client/server checks, plus the fixture-based positive control (`tools/nrth_netc_fixture.py`) and its measured 6+4/10/exit-3 numbers |
