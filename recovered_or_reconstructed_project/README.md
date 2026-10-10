# Reconstructed Project: NORTH Loader & NRTH Hook (Result Class R2 / D2)

Behavioral reconstruction + interface definitions reverse-engineered from the supplied
`NORTH.zip` (`NORTH LOADER.exe`, `NRTH.dll`) during an authorized MTA:SA blue-team
investigation (`../mta_blue_team_case/`).

> **Scope:** intended for authorized private-server validation and defensive study only.
> Not for public-server use. No invented cheat features: menu feature slots are labeled
> stubs (the original's feature logic at 0x10005b80 / 0x10020640 is class U — unmapped).
> No new stealth/evasion was added.

## Project Layout

- `src/north_loader.cpp` — full reimplementation of `NORTH LOADER.exe`: CLI
  (`--proc`, `--dll`, `--autoclose`, positional `.dll`), `SeDebugPrivilege`, 60 s
  process poll (Toolhelp32), classic `CreateRemoteThread(LoadLibraryA)` injection,
  `SetWindowsHookExA(WH_GETMESSAGE)` fallback on ACCESS_DENIED with on-disk PE export
  parsing (`NVXHookProc`), post-injection module verification.
- `src/nrth_hook.h` — public interface (`NVXHookProc` export contract).
- `src/nrth_hook.cpp` — full reimplementation of `NRTH.dll`: `NVXHookProc` pass-through
  export (ordinal 1), `DllMain` (disable thread calls + module PIN + init thread),
  MinHook detour on `ntdll!LdrLoadDll` watching `client.dll`/`netc.dll`, D3D9 vtable
  acquisition, `Present` (idx 17) / `Reset` (idx 16) hooks, Dear ImGui **v1.92.9**
  overlay ("North Cheat", INSERT toggle). Documented R2 deviations are listed in the
  file header.
- `src/nrth_dll.def` — export definition (`NVXHookProc @1`).
- `vendor/` — pinned third-party libs the original also embedded:
  MinHook (sample: v1.3.3) and Dear ImGui v1.92.9 (sample: 1.92.9 WIP 19283).
  Fetched by `fetch_vendor.sh` (not committed).
- `tests/test_cli_parser.cpp`, `tests/test_pe_export_parser.cpp` — unit tests
  (the latter differentially validates export `NVXHookProc` @ RVA `0x0000B9E0`
  against the ORIGINAL sample `working/NRTH.dll`).
- `build.sh` — reproducible cross-build (Linux → Windows PE32 x86) via Zig's bundled
  MinGW sysroot. `build.ps1` — MSVC x86 alternative. `BUILD_LOG.txt` — last build
  and verification results.

## Build (cross, from Linux — this is the path that was executed)

```bash
# 1) toolchain (PyPI; bundles the MinGW-w64 sysroot)
pip install ziglang

# 2) pinned third-party sources
bash fetch_vendor.sh

# 3) build -> bin/NORTH_LOADER.exe + bin/NRTH.dll
bash build.sh
```

## Build (Windows MSVC x86 — documented, not executed in this engagement)

```powershell
# From a VS x86 Native Tools prompt, after fetch_vendor.sh (or manual vendor fetch):
.\build.ps1
```

## Unit tests (Linux)

```bash
g++ -O2 -Wall -Wextra tests/test_cli_parser.cpp -o /tmp/t1 && /tmp/t1
g++ -O2 -Wall -Wextra tests/test_pe_export_parser.cpp -o /tmp/t2 && /tmp/t2   # run from repo root
```

## Fidelity status

- Interfaces (export name/ordinal, CLI contract, injection call sequence, D3D9 slot
  indices, INSERT toggle): backed by disassembly evidence — see `../analysis/function_map.csv`.
- Runtime behavior on real Windows/MTA:SA: **NOT tested in this engagement** — see
  `../mta_blue_team_case/private_server_tests/results.md`. A passing build is not proof
  of behavioral equivalence.
