# nrth_guard — server-side impossible-state validator (MTA:SA)

**Case:** `mta_blue_team_case` · **Class:** R2 (newly authored defensive code, evidence-driven) · **Date:** 2026-10-10
**Implements:** `mta_blue_team_case/mechanism_overview_ar.md` §8.2 — «التحقق من استحالة قيم الصحة/المال/المركبات يبطل أغلب الميزات أياً كان آلية عملها».

## Why this is the right place to intervene

| Fact from the case | Consequence for defence |
|---|---|
| The tool executes arbitrary Lua inside the **client's** Lua VM via a `client.dll` exec trampoline (`mechanism_vm_injection.md` §4, evidence VA 0x10025c3d) | any client-side check the tool can reach, it can disable — client trust is worthless here |
| The tool writes `0xC3` into a `netc.dll` routine (kill-switch, VA 0x10020640) | netcode-side/client integrity can be silently neutered, so detection must not depend on it |
| Features are flag-driven from the ImGui menu, applied through Lua/memory writes (mechanism doc §6, per-feature path = Tentative) | the *effect* is still replicated to the server as ordinary state (health/armor/money/velocity) — that is the one place it cannot hide |

So `nrth_guard` validates **replicated state on the server**, not the client, and not the DLL.

## Layout

```text
nrth_guard/
  meta.xml                     -- resource manifest; server scripts only, by design
  server/guard_logic.lua       -- pure rules engine (no MTA API): testable off-server
  server/guard_config.lua      -- tunables (all STARTING POINTS, see calibration)
  server/main.lua              -- MTA glue: poll timer, events, sqlite log, ladder
tests/
  test_guard.lua               -- 29 logic cases
  mock_mta.lua                 -- test double for the MTA server API
  test_main_integration.lua    -- 13 glue cases driven through the double
  run_tests.sh, lua_runner.py  -- runner (system Lua if present, else lupa from PyPI)
```

## Rules implemented

| Rule | Detects shape | Evidence used | Severity |
|---|---|---|---|
| `HEALTH_ABOVE_MAX` / `HEALTH_JUMP` | GodMode / Give HP | ceiling + rate of `getElementHealth` deltas | high / medium |
| `ARMOR_JUMP` | Give Armor | ceiling + rate of `getPedArmor` | medium |
| `MONEY_RATE` | Money Exploit | rate of `getPlayerMoney` deltas | high |
| `AMMO_RATE` | Infinite Ammo | rate of `getPedAmmunition` | medium |
| `TRAVEL_RATE` | Click Warp / teleport | `|Δpos|/Δt` from `getElementPosition` | high |
| `VEHICLE_SPEED` | AirBreak / speed | `|getElementVelocity|` in game units/s | medium |
| `JETPACK` | Jetpack | `getPedWeapon==46` without a server grant | high |
| `GODMODE` | invincibility | server damage ledger vs. frozen health over a window | high |
| `RESPAWN_HEAL` | instant heal abuse | Δhealth right after damage, no spawn grant | low |

Legitimate changes are whitelisted through **grant windows** (`onPlayerSpawn`, `nrthGuard:grant`, admin gives) instead of by relaxing thresholds — that is what keeps the rules tight without punishing normal play.

Sanction ladder: score decays over time; `warn` at `scoreWarnThreshold`, `kick` only at `scoreKickThreshold` **and** only if `banPolicy = "kick"`. Shipped default: `report_only`.

## Calibration required before any sanction (do not skip)

1. Run `private_server_tests` **T0** (clean client, real testers, ≥30 min) with the resource in `report_only`.
2. Dump `nrth_guard.db` `events` table; take p99.9 of each delta distribution.
3. Set each `*PerSec` ceiling to that value plus margin. `maxVehicleVelocityUnits` in particular has **no measured conversion** — it is compared in raw `|velocity|` precisely because a km/h factor was never verified on the team's build.
4. Only then move to `warn`, and consider `kick` per incident review.

## Known limitations (honest list)

* **Not executed on a live MTA server in this engagement** (Linux analysis host, no MTA runtime). The glue was exercised against `tests/mock_mta.lua`, which proves the code paths run as written — it does **not** prove MTA's real replication timing, function availability, or behaviour under load.
* The MTA API surface used is listed at the top of `main.lua`; verify every name/arity against your server version (docs for 1.5.x) before loading. `min_mta_version` in `meta.xml` is a placeholder.
* Rules keyed on state that MTA does **not** replicate server-side (e.g. overlay rendering, screenshot-hiding/"Anti-ScreenShot", local dumper actions, `netc.dll` patching itself) are out of scope here — that is `../integrity_probe/` and `telemetry.md`.
* `GODMODE` only works if something tells the guard that damage was applied (`nrthGuard:serverDamage`); without that feed the rule can never fire — it will not produce a verdict on its own.
* Rate rules are bypassable by a cheat that paces its writes (small steps spread over time) or that avoids replicated state entirely. Combine with `integrity_probe` + host telemetry; never rely on a single signal (see `../telemetry.md`).
* Deliberately **no** client-side detection code, no signature scanner, and no game-VM interaction — adding those would ship the cheat rather than the countermeasure.

## Run the tests

```bash
bash tests/run_tests.sh                                  # console
bash tests/run_tests.sh 2>&1 | tee ../../test_results/server_guard_logic_tests.log
```

Last executed result (this repo): `../../test_results/server_guard_logic_tests.log` — **29/29 logic + 13/13 glue checks passed**, exit 0. Interpreter: lupa (embedded Lua 5.x) via PyPI, no system Lua on the host.
