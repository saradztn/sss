# Private-Server Test Plan — NORTH/NRTH/NVX (MTA:SA)

Status: **PLAN ONLY — not executed in this engagement** (see `results.md`).
Purpose: measure the sample's real capability against a team-owned MTA:SA private server. This is a defensive validation exercise; it is explicitly **not** a license to use the sample on public servers or against third-party players.

## 0. Authorization & scope checklist (fill before any run)

- [ ] Written authorization for this exact sample (SHA-256 in `../hashes.sha256`) on the named private server.
- [ ] Server ownership/recorded: operator alias, server IP/hostname **(redact in reports)**, MTA:SA **server build** (e.g., 1.6.x-<commit>), client build used for testing.
- [ ] Dedicated test accounts (aliases only in logs, e.g., `test-cl-01`, `test-cl-02`); no real player accounts.
- [ ] Unrelated players excluded: server locked to test accounts (password/whitelist) for the test window.
- [ ] Backups: server `mods/deathmatch/resources`, `mtaserver.conf`, database — snapshot + timestamp before the first run.
- [ ] Rollback plan documented and rehearsed (restore snapshot; ban/cleanup test accounts).
- [ ] Stop conditions: any activity escaping the server/client scope, any unexpected file/registry persistence, any effect on production services → stop, roll back, preserve logs.

## 1. Environment record (fill at run time)

| Item | Value |
|---|---|
| Host OS / VM snapshot | (e.g., Windows 10 22H2, VM snapshot id) |
| MTA:SA client build | |
| MTA:SA server build | |
| Sample SHA-256 (loader) | 837650b9f1ca52d2c91c966ba7f16721986e754f3efdfb42a08536610067c5fb |
| Sample SHA-256 (DLL) | 947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861 |
| Test accounts (aliases) | |
| Baseline timestamp (UTC) | |
| Sample run timestamp (UTC) | |

## 2. Test matrix

Observe with: Process Monitor (filter: `gta_sa.exe`, loader), Process Explorer, ETW/WPR, x64dbg or WinDbg (loader only if needed), MTA server `debugscript 3` logs, server console, optional network capture on the server side. Record tool versions.

### T0 — Baseline (no sample)
1. Start the clean MTA:SA client, connect to the private server with `test-cl-01`.
2. Play 5 minutes: join, walk, drive, shoot, change resolution/windowed mode.
3. Capture: module list of `gta_sa.exe` (Process Explorer), Process Monitor log, server logs.
4. Expected: no `NRTH.dll`/`nvx.dll`, no alerts from `detection/telemetry.md` rules.

### T1 — Loader passive behavior
1. Run `NORTH LOADER.exe` with **no game running**. Expect: banner `=== NORTH Loader ===`, `[*] Esperando a gta_sa.exe ...`, timeout after ~60 s, exit code 1.
2. Record console output and process/network/file activity (expect: none beyond console). Validates `behavior_timeline.md` Stage 1–2 polling claims.

### T2 — Classic injection path
1. Start loader, then start MTA:SA client (windowed) and join the private server.
2. Expect within the poll window: `[+] Inyectado OK clasico (modulo=0x...)`.
3. Verify: `NRTH.dll` mapped into `gta_sa.exe` (Process Explorer modules / `K32EnumProcessModules` equivalent).
4. Sysmon correlation per `detection/telemetry.md` Layer 2 rule 1.

### T3 — Hook-injection fallback path
1. Configure the environment so `OpenProcess` returns ACCESS_DENIED (e.g., run the game elevated and the loader non-elevated — the exact trigger for status 2 in `InjectClassic`).
2. Expect: `[*] Export NVXHookProc en RVA 0x0000B9E0`, `[*] Hook instalado, despertando el hilo del juego...`, `[+] Inyectado OK por hook ...`.
3. Verify module load + the 10× `PostThreadMessageA(WM_NULL)` burst (API Monitor).

### T4 — Arming trigger (client.dll / netc.dll)
1. With the payload loaded (T2 or T3), attach WinDbg/x64dbg to `gta_sa.exe` **read-only** (no memory patches) and set a breakpoint on `ntdll!LdrLoadDll` return path or use API Monitor.
2. Expect: detour installed (ntdll `.text` write at `LdrLoadDll`); on load of `client.dll`/`netc.dll`, follow-on init routines (0x10005b80 / 0x10020640) execute. Record order/timing.

### T5 — Overlay & menu capability inventory
1. In-game on the private server, press INSERT. Expect ImGui menu titled "North Cheat" drawn over the frame (matches loader hint string).
2. Inventory each menu control (screenshot + note) and attempt each feature **only** against `test-cl-02` (consenting) or harmless world state.
3. For each feature: record observed effect, server-side log lines, and whether server-side validation rejected it. Classify each claim: observed / inferred / not reproduced.
4. Resize window / toggle fullscreen → overlay must survive (`Hooked_Reset` path).

### T6 — Negative controls & cleanup
1. Exit game; confirm loader exits; check `C:\NVX` for created files (existence Tentative in static analysis).
2. Revert VM snapshot; restore server snapshot if any resource changed.
3. Confirm no persistence (Run keys, services, scheduled tasks) and no residual accounts.

## 3. Recording template per claim

`Claim | Test id | Observed on this exact client/server build? | Evidence (log path, timestamp) | Verdict (observed / inferred / not reproduced)`
