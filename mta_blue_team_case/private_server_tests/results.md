# Private-Server Test Results — NORTH/NRTH/NVX

## Status: NOT EXECUTED (environment limitation)

No runtime testing against a real MTA:SA client/server was performed in this engagement. The analysis host available here is a **Linux sandbox without Windows, without an MTA:SA installation, and without a team-owned private server**, so executing the samples (Windows PE32 binaries) or standing up the authorized test environment was not possible.

Per the investigation policy, a simulation/mock must NOT be presented as proof of real behavior. Therefore:

| Test id | Description | Result |
|---|---|---|
| T0–T6 | Full matrix in `test_plan.md` | **Not executed** |
| Differential original-vs-reconstruction runs | Required before any equivalence claim | **Not executed** |

### Addendum 2026-10-10 (later run): what *is* executable without a Windows/MTA host

Two of the case's claims no longer need a runtime environment, and both were run on the Linux
analysis host (full log: `../test_results/run_all_tests.log` — `8 passed, 0 failed, 0 skipped`):

| Check | Command | Result |
|---|---|---|
| Detector logic | `./run_all_tests.sh` groups 1–2 | 27/27 unit tests, 21/21 self-test vectors (ciphertexts taken from the sample) |
| Interface contract of the reconstruction | group 4 | `NVXHookProc` located at RVA `0x0000B9E0` in the ORIGINAL `working/NRTH.dll` + negative case |
| False-positive control | group 5 | `nrth_audit audit` on `NRTH.dll` **and** `NORTH LOADER.exe` → 0 located-function footprints |
| Independent cross-implementation | group 5 | C++ `sweep --min 24` → the same 8 hidden `.data` records as `tools/nrth_sig_export.py` |
| A/B mode sanity | group 5 | `diff <image> <same image>` → no delta |
| Detection rules | group 6 | 4 YARA rules compile; `NRTH.dll` → 3 rules, loader → 1 rule; **our own `NRTH_audit.dll` / `.exe` match none** |

What still requires the private-server environment and is therefore **not** claimed: anything about
the cheat's runtime effect (menu features, gameplay/netcode impact, whether the six `netc.dll`
functions are the ones actually RET-killed on a live client, and which functions they are).

## What was validated instead (honest scope)

1. **Static validation (executed):** full disassembly of both samples with Capstone; the string layer
   was recovered later (82 decryptors / 63 plaintexts / 28 signature candidates, `../detection/recovered_strings.txt`),
   which is what turned `0x10005b80` and `0x10020640` from class U into mapped functions; PE structure parsing with `pefile`; export-table differential test of `NRTH.dll` (see `../test_results/test_pe_export_parser.log` — located `NVXHookProc` at RVA `0x0000B9E0`, matching the disassembly at VA `0x1000b9e0`).
2. **Reconstruction unit tests (executed, Linux/GCC 12.2.0):** CLI parser permutations and PE export parser — see `../test_results/*.log`. These validate *the reconstruction's* logic only; they are **not** evidence that the original samples behave identically at runtime.
3. **Reproduction fidelity status:**
   - Interface-level fidelity (export name/ordinal/RVA, CLI contract, injection call sequence): backed by disassembly evidence — Medium/High confidence as *static* fidelity.
   - Runtime fidelity (actual menu features, gameplay effects, network effects): **Unknown (U)** — untested here.

## Required next step

Execute `test_plan.md` on the team-owned private server (its T6 cleanup step now names the concrete
locations to inspect: `C:\Overwack\loader_config.cfg`, the ADS `C:\ProgramData:NT2`, and `C:\NVX`,
recording created/untouched for all three — negative results matter) with the recorded client/server builds, then replace this file with real logs and per-claim verdicts. Until then, every runtime behavior claim in the report remains **Observed (static)** or **Unknown**, never "verified live".
