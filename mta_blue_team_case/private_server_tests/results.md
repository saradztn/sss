# Private-Server Test Results — NORTH/NRTH/NVX

## Status: NOT EXECUTED (environment limitation)

No runtime testing against a real MTA:SA client/server was performed in this engagement. The analysis host available here is a **Linux sandbox without Windows, without an MTA:SA installation, and without a team-owned private server**, so executing the samples (Windows PE32 binaries) or standing up the authorized test environment was not possible.

Per the investigation policy, a simulation/mock must NOT be presented as proof of real behavior. Therefore:

| Test id | Description | Result |
|---|---|---|
| T0–T6 | Full matrix in `test_plan.md` | **Not executed** |
| Differential original-vs-reconstruction runs | Required before any equivalence claim | **Not executed** |

## What was validated instead (honest scope)

1. **Static validation (executed):** full disassembly of both samples with Capstone; PE structure parsing with `pefile`; export-table differential test of `NRTH.dll` (see `../test_results/test_pe_export_parser.log` — located `NVXHookProc` at RVA `0x0000B9E0`, matching the disassembly at VA `0x1000b9e0`).
2. **Reconstruction unit tests (executed, Linux/GCC 12.2.0):** CLI parser permutations and PE export parser — see `../test_results/*.log`. These validate *the reconstruction's* logic only; they are **not** evidence that the original samples behave identically at runtime.
3. **Reproduction fidelity status:**
   - Interface-level fidelity (export name/ordinal/RVA, CLI contract, injection call sequence): backed by disassembly evidence — Medium/High confidence as *static* fidelity.
   - Runtime fidelity (actual menu features, gameplay effects, network effects): **Unknown (U)** — untested here.

## Required next step

Execute `test_plan.md` on the team-owned private server with the recorded client/server builds, then replace this file with real logs and per-claim verdicts. Until then, every runtime behavior claim in the report remains **Observed (static)** or **Unknown**, never "verified live".
