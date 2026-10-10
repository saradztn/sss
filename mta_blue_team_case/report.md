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
- `NRTH.dll` — **in-game cheat overlay payload** for MTA:SA (High confidence): self-identified by its own `.rdata` strings `North Cheat` (VA 0x1000e90d8) and `Cheat` (VA 0x1000e94a0), armed specifically when MTA:SA modules `client.dll`/`netc.dll` load, drawing a Dear ImGui menu toggled by INSERT over the D3D9 frame.

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
- Use `C:\NVX` as a data/log directory (string decrypted; exact I/O unknown).

## 2. Reconstruction status

- **Exact original source recovered: NO.** No source files, PDB-with-source, or source archives were present in `NORTH.zip`. (A PDB *path* string exists in the loader — `C:\Users\user\Desktop\src CHEATS\over\Loader\Debug\NVX Loader.pdb` — but the PDB file itself is absent; per policy a PDB path is not source recovery.)
- **Result classes:**
  - `D2` — native decompilation/pseudocode: disassembly-based pseudocode of both samples (Capstone), documented in `analysis/` and referenced by `function_map.csv`.
  - `R2` — behavioral reconstruction: newly authored C++ in `recovered_or_reconstructed_project/` reimplementing the observed loader contract (CLI parsing, PE export parsing, documented injection sequence) for defensive study.
- **Original samples were not modified** (hashes re-verified before/after: `hashes.sha256`).
- **No capability was added** beyond the observed sample (no new stealth, persistence, or evasion). Where the original performs evasion-relevant actions (module pinning, string encryption, ntdll hook), they are *documented in analysis*; the reconstruction keeps them inert/documented rather than enhanced.

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

No Ghidra/IDA/Binary Ninja was available in this environment (network-restricted sandbox); a radare2 download attempt failed on the outbound allowlist. Disclosed as a coverage limitation.

## 5. Work performed (key evidence)

- **Phase 0–2:** read-only `evidence/` copy vs `working/` copy; SHA-256 before/after (unchanged); PE identification (see above); confirmed not packed (uniform low-entropy sections, `.text` entropy 4.75 loader / comparable DLL layout, full import tables).
- **Phase 3B (native):** disassembled entry points, exports, and core functions of both modules; every significant finding in `function_map.csv` carries VA/RVA and confidence. Highlights:
  - Loader: `main` 0x413170, `EnableDebugPrivilege` 0x411b20, `FindProcessByName` 0x411ea0, `InjectClassic` 0x412880, `InjectHook` 0x412470, `FindExportRvaInFile` 0x411ff0, `rva2off` 0x411960, `IsModuleLoadedInProcess` 0x412dc0.
  - DLL: `NVXHookProc` 0x1000b9e0 (export ordinal 1), `DllMain` 0x1000ba00, `MainInitThread` 0x1000a850, `Hooked_LdrLoadDll` 0x1000a640, `GetD3D9DeviceVTable` 0x10012980, `InstallD3D9Hooks` 0x10016500, `Hooked_Present` 0x10014d50, `Hooked_Reset` 0x1001a3c0, MinHook `MH_CreateHook` 0x10036020.
- **Phase 4:** strings catalog (9,452 lines) with section/offset mapping; high-value indicators extracted to `indicators.json`.
- **Phase 5 (dynamic):** **not executed** — no Windows/MTA environment (see §7). Plan recorded in `private_server_tests/test_plan.md`.
- **Phase 6:** behavioral reconstruction in `recovered_or_reconstructed_project/` (R2) with unit tests; validation checklist partially satisfied (build/test on Linux only; Windows ABI/runtime equivalence untested).
- **Phase 7:** this case folder (`report.md`, `hashes.sha256`, `file_inventory.csv`, `imports_exports.txt`, `strings_catalog.txt`, `function_map.csv`, `behavior_timeline.md`, `indicators.json`, `detection/`, `private_server_tests/`, `test_results/`).

## 6. Build & test commands and real results

```
$ g++ -std=c++17 -Wall -Wextra -o tests/test_cli_parser tests/test_cli_parser.cpp && ./tests/test_cli_parser
[+] All CLI parsing tests passed successfully!          # 4/4 cases (log: test_results/test_cli_parser.log)

$ g++ -std=c++17 -Wall -Wextra -o tests/test_pe_export_parser tests/test_pe_export_parser.cpp && ./tests/test_pe_export_parser working/NRTH.dll
[+] Located export 'NVXHookProc' at RVA: 0x0000B9E0 (Expected: 0x0000B9E0)
[+] Negative test passed: Non-existent export safely returns false.
[+] All PE export parser tests passed successfully!     # differential vs real sample (log: test_results/test_pe_export_parser.log)
```

Windows build script for the reconstruction (`recovered_or_reconstructed_project/build.ps1`, MSVC x86) is documented but **was not executed** here (no Windows/MSVC on the analysis host). Passing tests = compatibility for the covered contracts only; **not** proof of full behavioral equivalence.

## 7. Coverage, confidence, limitations

- **Covered (High confidence):** file identification, export/import maps, injection call chains, arming trigger, overlay infrastructure, operator UX strings, hash integrity.
- **Partially covered (Medium):** init routines 0x10005b80 / 0x10020640 (entry and trigger known; internal feature logic not fully mapped).
- **Unresolved (U):** exact menu feature set and any game-state/netcode effects; `C:\NVX` file I/O; whether `SWeaponAimSync` RTTI is used at runtime or merely linked; behavior under real anti-cheat products; private-server runtime results.
- **Environment limits:** Linux sandbox; no Ghidra/IDA (radare2 download blocked); no Windows runtime; no MTA:SA private server. Dynamic claims are therefore absent, not implied.
- **Sample-set limit:** 2 binaries; detection rules unvalidated against variant sets.

## 8. How to detect / How to defend

- **Detect:** see `detection/telemetry.md` (layered file + host + server signals with FP caveats) and `detection/yara_rules.yar` (3 candidate rules; exact-sample strength). Never rely on a single import/string.
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
| `detection/yara_rules.yar` | 3 candidate rules with confidence meta |
| `detection/telemetry.md` | Layered telemetry + FP caveats + regression tests + blind spots |
| `private_server_tests/test_plan.md` | Real client/server test matrix (T0–T6) |
| `private_server_tests/results.md` | Honest status: NOT EXECUTED + what was validated instead |
| `test_results/*.log` | Actual unit-test output (CLI parser, PE export differential) |
