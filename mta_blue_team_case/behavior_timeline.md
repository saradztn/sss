# Behavior Timeline — NORTH.zip (NRTH / NVX)

Case: MTA:SA blue-team investigation (`mta_blue_team_case/`)
Sample hashes: see `hashes.sha256`.
Evidence basis: static analysis only (Capstone disassembly + `pefile`/manual PE parsing on Linux analysis host). Items marked **Observed** are directly traceable to code/strings at the cited VA/RVA; **Strongly inferred** items follow from multiple corroborating indicators; **Unknown** items were not resolved.

Legend: [O] Observed · [SI] Strongly inferred · [T] Tentative · [U] Unknown

---

## Stage 0 — Operator action (outside the sample)

1. [O] Operator extracts `NORTH.zip` and runs `NORTH LOADER.exe` from a console (console subsystem; prints banner `=== NORTH Loader ===` at VA 0x419a48 region; `SetConsoleTitleA("NORTH Loader")`).
2. [O] CLI options are parsed in `main` (VA 0x413170 / RVA 0x13170):
   - default target process: `gta_sa.exe` (string at VA 0x419964)
   - default DLL: `NRTH.dll` beside the loader
   - `--proc <name>` overrides the target process name
   - `--dll <path>` or a positional `.dll` argument overrides the payload path
   - `--autoclose` exits without waiting for ENTER after injection

## Stage 1 — Loader preparation (NORTH LOADER.exe)

3. [O] `EnableDebugPrivilege` (VA 0x411b20 / RVA 0x11b20): `OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY)`, `LookupPrivilegeValueA("SeDebugPrivilege")` (string VA 0x419b30), `AdjustTokenPrivileges`. Purpose: open protected processes for injection.
4. [O] `FileExists` (VA 0x411ce0 / RVA 0x11ce0): `GetFileAttributesA` check that the DLL path exists and is not a directory. Abort with console error if missing.
5. [O] Poll loop in `main`: up to 600 iterations × `Sleep(100)` ≈ 60 s.
   - `FindProcessByName` (VA 0x411ea0 / RVA 0x11ea0): `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` + `Process32First/Next`, case-insensitive compare of `szExeFile` with `_stricmp`.
   - Console: `[*] Esperando a %s (abre el juego DESPUES del loader)...` ("waiting for the process — open the game AFTER the loader").
   - Timeout → `[!] Tiempo agotado esperando el proceso.` and exit 1.

## Stage 2 — Primary injection: classic remote thread

6. [O] `InjectClassic` (VA 0x412880 / RVA 0x12880), attempted first:
   - `OpenProcess(0x43a /* CREATE_THREAD|VM_OPERATION|VM_WRITE|QUERY_INFORMATION|... */, pid)`
   - `VirtualAllocEx(MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)` for the DLL path string
   - `WriteProcessMemory` writes the full DLL path
   - `CreateRemoteThread` starting at `kernel32!LoadLibraryA` (resolved via `GetProcAddress`)
   - `WaitForSingleObject(hThread, 15000)`; `GetExitCodeThread` → remote module handle
   - Cleanup: `VirtualFreeEx`, `CloseHandle`; console `[+] Inyectado OK clasico (modulo=0x%08lX)`
   - Failure classification: returns status 2 when `OpenProcess` fails with `ERROR_ACCESS_DENIED` (5); other failures return 1.

## Stage 3 — Fallback injection: WH_GETMESSAGE hook

7. [O] `InjectHook` (VA 0x412470 / RVA 0x12470) runs when `InjectClassic` returns 2 (access denied):
   - Loads the DLL locally: first `LoadLibraryA`; if that fails, `LoadLibraryExA(path, 0, DONT_RESOLVE_DLL_REFERENCES)` after manually parsing the on-disk PE export table.
   - `FindExportRvaInFile` (VA 0x411ff0 / RVA 0x11ff0) + `rva2off` (VA 0x411960 / RVA 0x11960): maps the file (`CreateFileA`/`CreateFileMappingA`/`MapViewOfFile`), validates `IMAGE_DOS_SIGNATURE`/`IMAGE_NT_SIGNATURE`, walks `IMAGE_EXPORT_DIRECTORY` for the name `NVXHookProc` (string VA 0x4196c4), prints `[*] Export NVXHookProc en RVA 0x%08lX`.
   - `FindThreadInProcess` (VA 0x411d80 / RVA 0x11d80): `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` → first thread of the target PID.
   - `SetWindowsHookExA(WH_GETMESSAGE=3, hookProc=NVXHookProc, hMod=payload, tid)`; then 10 × `PostThreadMessageA(tid, WM_NULL)` to wake the target thread into the hook. Console: `[*] Hook instalado, despertando el hilo del juego...`
   - `UnhookWindowsHookEx` immediately after; `IsModuleLoadedInProcess` (VA 0x412dc0 / RVA 0x12dc0) verifies via `K32EnumProcessModules`/`K32GetModuleBaseNameA` that `NRTH.dll` is now mapped into the target. Console: `[+] Inyectado OK por hook (modulo verificado en el proceso).`
   - Final hint: `[*] Hook completado. Entra al juego y pulsa INSERT: si sale el menu, quedo.` ("enter the game and press INSERT; if the menu appears, it worked").
8. [SI] Mechanism note: `SetWindowsHookEx` forces the Windows subsystem to `LoadLibrary` the payload into the target GUI thread's process — this is why the DLL exports a trivial `NVXHookProc` (see Stage 4.1).

## Stage 4 — Payload initialization (NRTH.dll inside gta_sa.exe / MTA)

9. [O] `NVXHookProc` (export ordinal 1, VA 0x1000b9e0 / RVA 0x0b9e0): 4-instruction stdcall thunk → `CallNextHookEx(NULL, nCode, wParam, lParam)`. Functional role: hook-procedure contract only (enables Stage 3); no game logic.
10. [O] CRT entry (VA 0x100a8bb0 / RVA 0x0a8bb0) → `DllMain` (VA 0x1000ba00 / RVA 0x0ba00) on `DLL_PROCESS_ATTACH`:
    - `DisableThreadLibraryCalls(hMod)`
    - `GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN=5, ...)` — **pins the module so it cannot be unloaded** (self-protection observable; no new behavior added in reconstruction).
    - `CreateThread` → `MainInitThread` (VA 0x1000a850 / RVA 0x0a850).
11. [O] `MainInitThread` (VA 0x1000a850 / RVA 0x0a850):
    - Decrypts embedded strings (per-length positional XOR, `plain[p] = cipher[p] ^ ((p-K)&0xFF)`, one K per decryptor — 82 decryptors / 63 plaintexts recovered in `working/recovered.json`; recovered names include `client.dll`, `netc.dll`, `@auto_inject`, the MTA registry keys, `C:\Overwack\loader_config.cfg` and `C:\ProgramData:NT2`. `C:\NVX` (VA 0x100b0d18) and `@custom` (.rdata 0x100ea890) are **plain** strings, not decodes — corrected after the decode pass.
    - `GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll")`.
    - MinHook v1.3.3 (`MH_Initialize`, `MH_CreateHook` at VA 0x10036020, `MH_EnableHook`) installs an inline detour on `ntdll!LdrLoadDll` → handler at VA 0x1000a640.
12. [O] `Hooked_LdrLoadDll` (VA 0x1000a640 / RVA 0x0a640): passes every load through to the original `LdrLoadDll`, then inspects the loaded module name. When `client.dll` or `netc.dll` appear (MTA:SA client modules), it triggers the follow-on initialization routines (decompiler labels `0x10005b80`, `0x10020640`).
    - [SI] Trigger rationale: these modules only exist inside the MTA:SA client, so the payload waits until the multiplayer framework is loaded before arming itself.

## Stage 5 — Overlay arming (D3D9)

13. [O] `GetD3D9DeviceVTable` (VA 0x10012980 / RVA 0x12980): loads/inspects `d3d9.dll` in the game process and pattern-scans for the `IDirect3DDevice9` vtable pointer assignment (byte patterns `C7 06 ...` / `89 86 ...`).
14. [O] `InstallD3D9Hooks` (VA 0x10016500 / RVA 0x16500): MinHook detours on
    - vtable slot 17 (offset 0x44) `IDirect3DDevice9::Present` → `Hooked_Present` (VA 0x10014d50 / RVA 0x14d50)
    - vtable slot 16 (offset 0x40) `IDirect3DDevice9::Reset` → `Hooked_Reset` (VA 0x1001a3c0 / RVA 0x1a3c0)
15. [O] `Hooked_Present`: runs a Dear ImGui 1.92.9 WIP (19283) frame each present (`ImGui::NewFrame` / `Render` / `ImGui_ImplDX9_RenderDrawData`). Overlay window identifiers in `.rdata`: `%s##nvx_top_%d`, `##nvx_content` (VA 0x100ea4b0 region). Toggle key: `Insert` (ImGui key name, VA 0x100ec8b4) — matches the loader's operator hint.
16. [O] `Hooked_Reset`: `ImGui_ImplDX9_InvalidateDeviceObjects` before the original `Reset`, `CreateDeviceObjects` after — survives resolution changes/windowed toggles.
17. [O] Overlay self-identification strings in NRTH.dll `.rdata`. Address convention used in this
    file: `VA` = ImageBase + RVA as loaded; `off` = raw file offset in the packed file (for `.rdata`
    of this module, RVA = off + 0x1000). 11 claims were re-verified and corrected on 2026-10-11 with
    `recovered_or_reconstructed_project/tools/nrth_string_va.py` — do not re-derive them by eye.
    - `North Cheat` (VA 0x100ea0d8)
    - `Cheat` (VA 0x100ea4a0)
    - `Menu Toggle Key` (VA 0x100ec114)
    - `.?AUSWeaponAimSync@@` (MSVC RTTI for `SWeaponAimSync`, an MTA:SA weapon-aim sync struct; VA 0x1013c154 in `.data`)
    - `PACKET_ID_CHEAT_CHALLENGEMEMORY`, `PACKET_ID_CHEAT_RETURN`, `PACKET_ID_MTA_RESERVED_*` (VA 0x100eb6a8 region) — MTA:SA network protocol identifiers present in the binary (embedded netcode constants from the MTA client codebase).

## Stage 6 — Runtime (menu usage)

18. [O] Operator presses INSERT in-game → ImGui menu named "North Cheat" is drawn over the D3D9 frame.
19. [O→] The two initialization routines are now mapped at instruction level (2026-10-10 decode pass):
    - `0x10005b80` decrypts 11 hidden x86 patterns and installs 11 MinHook detours in `client.dll` (detours 0x10002ff0/47b0/50a0/5290/52b0/5620/56c0/56f0/5ab0/5b30/5b50); `0x1000c390` runs 20 pattern scans with **no** hooking (offset/field resolver; role [I]).
    - `0x10020640` (prologue `53 8B DC`) decrypts `netc.dll` + a target pattern, resolves it via `0x10002960`, and writes a single `0xC3` over **six** functions through writer `0x10011870` (`VirtualProtect(…,0x40,…)` + 1-byte copy) at sites 0x100206f0/0x100208aa/0x10020927/0x10020f46/0x100214bd/0x100215f1; their target patterns live only in `.data` globals at run time, so the *identity* of the six functions stays [U].
    - Refined 2026-10-11 (`tools/nrth_report_path_check.py payload`): each of those six VAs is a `call rel32` to the writer, and the value is staged exactly **11 bytes earlier** by `mov byte ptr [ebp-disp8],0xC3` - measured staging VAs 0x100206e5, 0x1002089f, 0x1002091c, 0x10020f3b, 0x100214b2, 0x100215e6; 6/6 pairs and no other site of that form anywhere in the executable section. Read together with the co-located `Error #10XX Send screen error dev-cheat` strings, the targets are the **report** channels (screenshot / transgression / diagnostic), not generic self-integrity checks; earlier wording in this folder said "integrity checks" and has been corrected in `reconstruction_parity.md`, `detection/audit_tool.md` and `detection/recovered_strings.txt`.
    The menu's per-feature effect mapping is still [U]: it needs dedicated per-flag call-graph work plus, per policy, private-server runtime validation which was **not executed** here (see `private_server_tests/results.md`).
20. [U] No network egress, Run-key/service persistence, or credential access was observed in the static triage. Filesystem-related strings: `C:\Overwack\loader_config.cfg` (decoded; config read/write [I]), `C:\ProgramData:NT2` (decoded; an NTFS alternate data stream [O for the string, U for the use]), MTA's own `Common\data\cache` (decoded), and `C:\NVX` (plain string, use [U]). `Software\...\Internet Settings\Connections` and `Explorer\CLSID` reads were recovered, which is a *read* of proxy/shell state, not persistence evidence.

---

## Summary of trigger conditions

| Trigger | Effect | Evidence |
|---|---|---|
| Loader started, game not yet running | Loader polls ≤60 s for `gta_sa.exe` (or `--proc`) | `main` RVA 0x13170 |
| Target process appears | Classic injection attempt | `InjectClassic` RVA 0x12880 |
| `OpenProcess` denied (ERROR_ACCESS_DENIED=5) | WH_GETMESSAGE hook fallback | `InjectClassic` return 2 → `InjectHook` RVA 0x12470 |
| `NRTH.dll` mapped (either path) | Pin module, spawn init thread | `DllMain` RVA 0x0ba00 |
| `client.dll` or `netc.dll` load inside target | Cheat init routines fire | `Hooked_LdrLoadDll` RVA 0x0a640 |
| Each D3D9 `Present` | ImGui overlay drawn (toggle: INSERT) | `Hooked_Present` RVA 0x14d50 |
| D3D9 `Reset` (resize/mode change) | Overlay device objects rebuilt | `Hooked_Reset` RVA 0x1a3c0 |
