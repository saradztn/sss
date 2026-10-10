# Reconstructed Project: NORTH Loader & NRTH Hook

This directory contains the behavioral reimplementation (Result Class **R2**) and interface definitions reverse-engineered from the supplied `NORTH.zip` package (`NORTH LOADER.exe` and `NRTH.dll`).

## Project Layout

- `src/`
  - `north_loader.cpp`: Complete C++ behavioral reimplementation of `NORTH LOADER.exe` matching all CLI parameters, process detection, privilege escalation, classic `CreateRemoteThread` injection, and fallback `SetWindowsHookEx` injection.
  - `nrth_hook.h`: Public C interface definition for `NRTH.dll`, exporting `NVXHookProc`.
  - `nrth_hook.cpp`: Behavioral reconstruction of `NRTH.dll` showing DllMain pinning, initialization thread, and Direct3D 9 hook structure.
- `tests/`
  - `test_cli_parser.cpp`: Unit tests validating command-line parsing rules.
  - `test_pe_export_parser.cpp`: Differential verification test that directly parses `NRTH.dll` to find export `NVXHookProc` at RVA `0x0000B9E0`.

## Build Instructions

### Windows (MSVC)
Open the Visual Studio Developer Command Prompt (x86 Native Tools):

```cmd
# Compile NORTH Loader executable
cl.exe /nologo /O2 /W3 /MT /EHsc src\north_loader.cpp /link /OUT:NORTH_LOADER.exe advapi32.lib user32.lib psapi.lib

# Compile NRTH DLL
cl.exe /nologo /O2 /W3 /MT /LD /EHsc src\nrth_hook.cpp /link /OUT:NRTH.dll user32.lib d3d9.lib
```

### Windows (PowerShell)
Run `build.ps1` in a Visual Studio x86 Developer environment.

### Linux / Cross-Compilation Verification
Run the unit test suite on Linux:

```bash
g++ -O2 -Wall -Wextra tests/test_cli_parser.cpp -o tests/test_cli_parser && ./tests/test_cli_parser
g++ -O2 -Wall -Wextra tests/test_pe_export_parser.cpp -o tests/test_pe_export_parser && ./tests/test_pe_export_parser
```
