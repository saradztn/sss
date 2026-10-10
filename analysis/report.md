# Binary Reverse Engineering Report: NORTH.zip (NORTH LOADER.exe & NRTH.dll)

## 1. Executive Result and Result Classification

- **Primary Result Class:** **R2 — Reconstructed Implementation** (Newly authored source based on reverse-engineered behavior, disassembly, and interfaces).
- **Secondary Result Class:** **D2 — Native-code Decompilation / Pseudocode** (for disassembled binary routines and control-flow models).
- **Exact Original Source Recovered:** **No**. Neither binary contained original high-level C/C++ source code, project files, or uncompiled artifacts. All C/C++ source code delivered in `recovered_or_reconstructed_project/` is a newly authored behavioral reimplementation and interface specification.
- **Build Status:** Built and verified (unit test binaries built and passed under GCC 12.2.0; MSVC build scripts provided for Windows target).
- **Validation Status:** Tested (differential parsing of `NRTH.dll` export directory and CLI argument parser unit tests).

---

## 2. File Identification and Hashes

All inputs were cataloged upon receipt. Hashes were calculated before analysis and verified against read-only evidence copies.

| File Name | Size (Bytes) | SHA-256 Hash | Format / Arch | Subsystem | Entry Point RVA |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `NORTH.zip` | 772,837 | `f7130e5cb949a6049d5eab7042c1fa781d485abd392f2e325f493691ad369705` | ZIP Archive | N/A | N/A |
| `NORTH LOADER.exe` | 51,200 | `837650b9f1ca52d2c91c966ba7f16721986e754f3efdfb42a08536610067c5fb` | PE32 (x86 32-bit) | Win32 Console (CUI) | `0x11212` |
| `NRTH.dll` | 1,318,400 | `947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861` | PE32 (x86 32-bit DLL) | Win32 CUI (DLL) | `0xa8bb0` |

### Runtime & Toolchain Profile
- **`NORTH LOADER.exe`**: Compiled with Microsoft Visual C++ in **Debug** configuration (linked against `VCRUNTIME140D.dll` and `ucrtbased.dll`; contains `.msvcjmc` section and unstripped debug strings).
  - PDB debug path embedded: `C:\Users\user\Desktop\src CHEATS\over\Loader\Debug\NVX Loader.pdb`
- **`NRTH.dll`**: Compiled with Microsoft Visual C++ in **Release** configuration (linked against `MSVCP140.dll`, `VCRUNTIME140.dll`, `ucrt` DLLs, `gdiplus.dll`, `IMM32.dll`, `USER32.dll`, `ADVAPI32.dll`, `KERNEL32.dll`).

---

## 3. Tools and Versions Used

- **`pefile` v2024.8.26**: PE header parsing, section metadata, import/export directory analysis, and memory-mapped address calculations.
- **`capstone` v5.0.7**: X86 32-bit linear disassembly and instruction flow recovery.
- **`objdump` (GNU Binutils for Debian) v2.40**: Disassembly and verification of MSVC thunk tables.
- **`strings` / Python regex string extraction**: ASCII and UTF-16LE string analysis.
- **`gcc / g++` v12.2.0**: Compilation and execution of algorithm validation unit tests.

---

## 4. Reverse Engineering Analysis and Evidence

### 4.1. NORTH LOADER.exe Behavioral Reconstruction
`NORTH LOADER.exe` is a 32-bit injection utility designed to inject `NRTH.dll` into a target process (defaulting to `gta_sa.exe`).

1. **Entry Point & Command Line Arguments (`0x00413170`):**
   - Sets console title to `"NORTH Loader"`.
   - Defaults `app = "gta_sa.exe"` and target DLL to `<loader_directory>\NRTH.dll`.
   - Supports CLI flags:
     - `--autoclose`: Bypasses the final `Pulsa ENTER para salir...` prompt.
     - `--proc <name>`: Overrides target process name.
     - `--dll <path>`: Overrides payload DLL path.
     - Positional `<path.dll>`: Automatically assigns the DLL path if ending in `.dll`.
2. **Privilege Elevation (`0x00411b20`):**
   - Calls `OpenProcessToken` with `TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY`.
   - Resolves `"SeDebugPrivilege"` via `LookupPrivilegeValueA` and enables it with `AdjustTokenPrivileges`.
3. **Target Polling (`0x00411ea0`):**
   - Loops up to 600 times with a 100ms delay (`Sleep(100)`), for a maximum 60-second timeout.
   - Searches running processes using `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` and `Process32First/Next` comparing `szExeFile` with case-insensitive `_stricmp`.
4. **Primary Injection: Classic `CreateRemoteThread` (`0x00412880`):**
   - Calls `OpenProcess` with `PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ` (`0x43A`).
   - Allocates memory with `VirtualAllocEx(PAGE_READWRITE)` and writes the DLL path via `WriteProcessMemory`.
   - Resolves `LoadLibraryA` from `kernel32.dll` and invokes `CreateRemoteThread`.
   - Waits up to 15,000ms (`WaitForSingleObject`) and verifies the returned module handle via `GetExitCodeThread`.
5. **Fallback Injection: `SetWindowsHookEx` (`0x00412470`):**
   - If `OpenProcess` fails with `ERROR_ACCESS_DENIED` (code 5), the loader falls back to Windows hook injection.
   - Verifies the DLL exports `NVXHookProc`:
     - If local `LoadLibraryA` fails (e.g. missing dependencies), it parses the PE headers on disk using an internal PE parser (`FindExportRvaInFile` at `0x00411ff0` and `rva2off` at `0x00411960`) and loads with `LoadLibraryExA(..., DONT_RESOLVE_DLL_REFERENCES)`.
   - Finds an active thread in the target process via `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)` (`FindThreadInProcess` at `0x00411d80`).
   - Installs a thread-specific hook via `SetWindowsHookExA(WH_GETMESSAGE, pfn, hMod, threadId)`.
   - Posts 10 wake messages via `PostThreadMessageA(threadId, WM_NULL, 0, 0)` with 200ms intervals, then sleeps 500ms.
   - Unhooks with `UnhookWindowsHookEx` and frees the local library handle.
   - Verifies injection success by checking `K32EnumProcessModules` (`IsModuleLoadedInProcess` at `0x00412dc0`).

### 4.2. NRTH.dll Behavioral Analysis
`NRTH.dll` is an x86 native library for Multi Theft Auto: San Andreas (MTA:SA) providing a DirectX 9 Dear ImGui graphical overlay.

1. **Export Table:**
   - Single exported procedure: `NVXHookProc` at RVA `0x0000B9E0` (Ordinal 1).
   - Implementation: Immediately passes parameters to `CallNextHookEx(NULL, nCode, wParam, lParam)`. Its role is strictly to serve as a valid hook procedure for `SetWindowsHookEx`.
2. **DLL Lifecycle (`0x1000ba00`):**
   - Upon `DLL_PROCESS_ATTACH`: calls `DisableThreadLibraryCalls`.
   - Calls `GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN)` on itself to prevent premature unloading.
   - Spawns background worker thread `MainInitThread` at `0x1000a850`.
3. **Core Initialization & Hooking (`0x1000a850`):**
   - Uses compile-time XOR/SSE string encryption. Deobfuscated strings include:
     - `ntdll.dll`, `LdrLoadDll`, `client.dll`, `netc.dll` (decoded). `C:\NVX` is a PLAIN .rdata string
       at 0x000afd18 — see the corrected sections in `../mta_blue_team_case/`.
   - Installs an inline detour (MinHook v1.3.3) on `ntdll!LdrLoadDll` (`Hooked_LdrLoadDll` at `0x1000a640`).
   - Intercepts dynamic DLL loading inside `gta_sa.exe`:
     - When `client.dll` (MTA Client) loads: installs Direct3D 9 hooks.
     - When `netc.dll` (MTA NetClient) loads: initializes network client hooks.
4. **Direct3D 9 Device Hooking & UI Rendering:**
   - Scans `d3d9.dll` in memory for `IDirect3DDevice9` vtable patterns (`C7 06` / `89 86` device creation opcodes).
   - Detours `IDirect3DDevice9::Present` (vtable index 17 / offset `0x44`) at `0x10014d50`.
   - Detours `IDirect3DDevice9::Reset` (vtable index 16 / offset `0x40`) at `0x1001a3c0` for device loss handling.
   - Embeds **Dear ImGui 1.92.9 WIP (19283)** with a DirectX 9 backend.
   - Toggles UI visibility upon receiving `VK_INSERT` keypress.

---

## 5. Evidence and Confidence Rubric

| Finding | Evidence | Confidence | Alternative Explanations | Next Verification Step |
| :--- | :--- | :--- | :--- | :--- |
| Target binary architecture is 32-bit x86 PE (PE32) | PE Machine `0x14c`, Magic `0x10b`, COM/CLR descriptor absent (`Size=0, VA=0`) | High | None; strictly defined by PE/COFF standard | None needed |
| Original source files are not present in binary | Absence of source sections or source-link metadata; compiled machine code with optimization and CRT thunks | High | None | Complete decompilation and behavioral reconstruction |
| `NORTH LOADER.exe` was built in MSVC Debug mode | Linked to `VCRUNTIME140D.dll`, `ucrtbased.dll`; contains `.msvcjmc` section and RTC check strings | High | Debug build flags inadvertently enabled in release | Verified by section table and import table |
| `NVXHookProc` is a dummy export for `SetWindowsHookEx` | Disassembly shows only `CallNextHookEx` call with `ret 0xc`; loader calls `SetWindowsHookEx(WH_GETMESSAGE)` | High | Unfinished callback logic | Corroborated by loader injection routine |
| Target game is GTA:SA / MTA:SA | Default process `gta_sa.exe`; deobfuscated DLL strings `client.dll` and `netc.dll`; D3D9 hook | High | Other games named gta_sa.exe (extremely improbable) | Differential runtime execution in an isolated sandbox |

---

## 6. Verification and Test Results

Two automated validation tests were written and executed in the local environment:
1. `test_cli_parser`: Validated all 4 CLI parsing scenarios (default values, explicit flags, `--autoclose`, and positional `.dll` matching). All test assertions passed (Exit code: 0).
2. `test_pe_export_parser`: Implemented the reverse-engineered `FindExportRvaInFile` and `rva2off` logic in C++ and ran it directly against `working/NRTH.dll`. Verified that `NVXHookProc` was resolved at exact RVA `0x0000B9E0`, matching the original binary.

---

## 7. Deliverables Summary

- `analysis/report.md`: Reverse engineering report and evidence ledger.
- `analysis/file_inventory.csv`: Complete metadata, sizes, hashes, and classifications for all files.
- `analysis/hashes.sha256`: Cryptographic SHA-256 hashes of inputs and outputs.
- `analysis/imports_exports.txt`: Disassembled export tables and full import catalogs.
- `analysis/strings_catalog.txt`: Catalog of ASCII and Unicode strings with raw offsets and section mapping.
- `analysis/function_map.csv`: Complete function mapping table with addresses, roles, and confidence levels.
- `analysis/test_results/`: Logs from test execution.
- `recovered_or_reconstructed_project/`:
  - `src/north_loader.cpp`: C++ behavioral reimplementation of the loader.
  - `src/nrth_hook.h`: Interface header defining `NVXHookProc`.
  - `src/nrth_hook.cpp`: C++ behavioral reconstruction of the hook DLL.
  - `tests/test_cli_parser.cpp`: Unit tests for command-line handling.
  - `tests/test_pe_export_parser.cpp`: Differential PE export parsing test.
  - `README.md` & `build.ps1`: Build instructions and scripts.
