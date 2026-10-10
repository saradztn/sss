# Detection & Telemetry Guidance — NORTH/NRTH/NVX (MTA:SA)

Case: `mta_blue_team_case`. All signals below are tied to observed behavior (see `behavior_timeline.md`). Each rule lists false-positive (FP) caveats; **do not treat any single signal as definitive**. Prefer 2+ independent signals before verdicts or enforcement.

## Layer 1 — File/host indicators (static)

| Signal | Source evidence | Strength | FP caveats |
|---|---|---|---|
| SHA-256 of the two samples | `hashes.sha256` | High (exact) | Trivially bypassed by recompilation; treat as retro-hunting only |
| Export `NVXHookProc` in a DLL | NRTH.dll export table, ordinal 1, RVA 0x0B9E0 | Medium | Any DLL built for `SetWindowsHookEx` injection has a hook-proc export; name is family-specific |
| Strings `=== NORTH Loader ===`, `NVX Loader.pdb`, `[+] Inyectado OK` (Spanish console) | loader `.rdata` | High | Renamed/recompiled loaders lose them |
| `North Cheat` / `%s##nvx_top_%d` / `##nvx_content` | NRTH.dll `.rdata` | High | None likely for the exact strings; renamed clones may drop them |
| PDB path `C:\Users\user\Desktop\src CHEATS\over\Loader\Debug\NVX Loader.pdb` | loader `.rdata` 0x419aa4 | Medium | Developer artifact; may appear in other builds from the same source tree |
| Filesystem dir `C:\NVX` | decrypted string (NRTH.dll) | Medium | Generic folder name — corroborate with child files/timestamps near game sessions |
| Watch filename `NRTH.dll` / `nvx.dll` loaded into `gta_sa.exe` | loader default path + NRTH.dll string 0x1000f5cb2 | High in this context | DLL names are changeable; module-in-game-context is the key part |

## Layer 2 — Behavioral telemetry (host EDR/Sysmon/ETW)

Recommended event sources: Sysmon (EID 1, 7, 8, 10, 25), Windows Security 4688 with command-line, ETW `Microsoft-Windows-Kernel-Process`, API-level EDR.

1. **Injection chain (BHVR-1+2)** — parent process opens `gta_sa.exe`/MTA with `PROCESS_VM_WRITE|PROCESS_CREATE_THREAD`, allocates remote memory, writes a path ending in `.dll`, then creates a remote thread whose start address resolves to `LoadLibraryA`.
   - Sysmon correlate: EID 10 (ProcessAccess to game with VM_WRITE) + EID 8 (CreateRemoteThread, start module kernel32!LoadLibraryA) + EID 7 (image load of `NRTH.dll` into `gta_sa.exe` shortly after).
   - FP: legitimate injectors (Steam overlay, Discord, graphics tools, AV) — allowlist by signer and module hash.

2. **Hook-injection fallback (BHVR-3)** — `SetWindowsHookExA(WH_GETMESSAGE, ...)` targeting a thread of the game process, followed by `PostThreadMessageA` bursts (10× `WM_NULL`), immediate `UnhookWindowsHookEx`, then module verification via `K32EnumProcessModules`.
   - Correlate with the hook module being unsigned/unknown and the loader's console parentage.
   - FP: IMEs, accessibility tools, clipboard managers use hooks heavily — the *target being the game + the export name + the verify-then-unhook pattern* is the discriminator.

3. **Payload arming (BHVR-4)** — inside `gta_sa.exe`: `GetModuleHandleExA` with `GET_MODULE_HANDLE_EX_FLAG_PIN` on an unsigned third-party DLL, followed by `VirtualProtect` writes inside `ntdll.dll` (MinHook trampoline on `LdrLoadDll`).
   - ntdll `.text` write-protection-change events from a non-Microsoft module are high-value on their own.
   - FP: some overlay/anti-cheat products patch ntdll too — verify signer/allowlist.

4. **Overlay (BHVR-5)** — repeated calls into D3D9 Present from a module that is not the game/graphics stack; device `Reset` followed by texture recreation patterns (ImGui device-object lifecycle).
   - FP: Steam/Discord/ReShade overlays — baseline a clean client image first (see `private_server_tests/test_plan.md`).

5. **MTA interop (BHVR-6)** — a non-MTA-signed module referencing `client.dll`/`netc.dll` load events, or MTA packet-ID constants. On the server side: unexpected packet-ID sequences (`PACKET_ID_CHEAT_*`-class handlers), memory-challenge responses arriving without a corresponding server challenge.

## Layer 3 — Server-side (MTA:SA private server)

- Treat client-side state as untrusted: validate movement/aim/weapon sync server-side (rate checks, impossible-state checks on `SWeaponAimSync`-class structures).
- Log module-load attestations if your anti-cheat supports client module inventories; alert on unsigned DLLs mapped into `gta_sa.exe` after game start.
- Enable verbose netcode logging around reserved/cheat packet IDs during investigations; capture with server resources, not by inspecting third-party players' machines.

## Layer 4 — tooling now available in this case folder

| Tool | Covers | Status |
|---|---|---|
| `server_validation/nrth_guard/` (MTA server resource) | impossible/rate-invalid replicated state: health, armor, money, ammo, travel, vehicle velocity, jetpack, godmode-corroboration | **built + 42 checks passing off-server** (`../test_results/server_guard_logic_tests.log`); NOT yet run on a live MTA server |
| `integrity_probe/nrth_probe.py` (host, read-only) | in-memory `.text` diffs of `client.dll`/`netc.dll`/`ntdll.dll`/`d3d9.dll` vs a clean baseline; classifies `HOOK_JMP`, `HOOK_PUSH_RET`, `EARLY_RET` (the sample's `0xC3` kill-switch shape) | **logic unit-tested (36 checks, `../test_results/integrity_probe_logic.log`)**; live baseline/check not executed (no Windows/MTA here) |
| `private_server_tests/expected_alerts.csv` | per-stage "which tool must light up" matrix, wired to `behavior_timeline.md` | prepared; to be filled with real results during T0–T6 |

Deployment order that keeps false positives survivable: run `nrth_guard` in `report_only` for a full T0 baseline → calibrate → keep `nrth_probe` baselines per client build → only then enable `warn`/`kick`.

## Regression tests for your detections

1. Run the clean MTA:SA client → record baseline telemetry (must generate zero alerts from rules 1–5 except known overlay FP list).
2. Run the sample on the team's private server per `private_server_tests/test_plan.md` → each step of `behavior_timeline.md` must produce the corresponding alert.
3. Recompile-style variants (renamed export/strings) will evade Layer 1 → Layer 2/3 rules are the safety net; validate them with the reconstruction in `recovered_or_reconstructed_project/` **only inside the authorized private-server scope**.

## Known blind spots (honest list)

- Strings in the payload are XOR/SSE-encrypted; variant builds with a different key evade string rules entirely.
- Export renaming defeats `NVXHookProc`-based rules.
- No rule here has been validated against a broader variant set — the sample set is exactly 2 files + 1 archive.
- Kernel-mode or manual-map injectors would evade all module-load-based signals (not observed in this sample family).
