-- ===========================================================================
-- test_main_integration.lua — drives nrth_guard/server/main.lua against mock_mta
-- ===========================================================================
local here = ...
if not here or here == "" then here = "." end
local root = here

local function run(path) return assert(loadfile(path), "cannot load " .. path)() end

run(root .. "/nrth_guard/server/guard_logic.lua")
run(root .. "/nrth_guard/server/guard_config.lua")
run(root .. "/tests/mock_mta.lua")
local Mock = Mock   -- mock_mta exposes the Mock table as a global
run(root .. "/nrth_guard/server/main.lua")

local pass, fail = 0, 0
local function check(name, cond, extra)
    if cond then pass = pass + 1; print("  [PASS] " .. name)
    else fail = fail + 1; print("  [FAIL] " .. name .. (extra and (" :: " .. tostring(extra)) or "")) end
end

print("== nrth_guard MTA-glue integration tests (test doubles, NOT live MTA) ==")

-- resource start wires a poll timer and opens the sqlite log
Mock.reset()
Mock.settick(1000)
Mock.fire("onResourceStart")
check("onResourceStart created a poll timer", next(Mock.timers) ~= nil)
check("startup banner logged", Mock.logContains("[nrth_guard] started"), Mock.log[1])

-- clean player: several polls, no findings
local p = Mock.newPlayer("alice")
for i = 1, 20 do Mock.settick(1500 + i * 500); Mock.tickTimers() end
check("clean player produced no FINDING lines", not Mock.logContains("FINDING"), #Mock.log)

-- money exploit while polling -> server-side detection + report action
p.money = 4000000
Mock.settick(12000)
Mock.tickTimers()
check("FINDING/MONEY_RATE logged for instant money jump", Mock.logContains("MONEY_RATE"), table.concat(Mock.log, " | "))
check("finding row written to sqlite", #Mock.dbRows > 0, #Mock.dbRows)
check("default policy is report (no kick)", #Mock.kicks == 0, #Mock.kicks)

-- helper: restart the resource cleanly (main.lua keeps its timer handle across resets)
local function restart()
    Mock.fire("onResourceStop")   -- glue kills its own poll timer here
    Mock.reset()
    Mock.fire("onResourceStart")
end

-- spawn grant path must not raise a heal false positive
restart()
local q = Mock.newPlayer("bob", { health = 12, armor = 0 })
Mock.settick(5000); Mock.tickTimers()          -- baseline
Mock.settick(5500); q.health = 100; q.armor = 50
Mock.fire("onPlayerSpawn", q)                  -- legit spawn
Mock.tickTimers()
check("spawn grant suppresses HEALTH_JUMP in glue", not Mock.logContains("HEALTH_JUMP"), table.concat(Mock.log, " | "))

-- wasted resets the baseline
Mock.settick(6000); Mock.tickTimers()
Mock.settick(6500); q.health = 100; q.armor = 100
Mock.fire("onPlayerWasted", q)
Mock.tickTimers()
check("respawn after waste is not flagged", not Mock.logContains("HEALTH_JUMP"), table.concat(Mock.log, " | "))

-- admin/weapon-grant RPC channel exists and is wired
check("nrthGuard:grant event registered", Mock.events["nrthGuard:grant"] == true)
check("nrthGuard:serverDamage event registered", Mock.events["nrthGuard:serverDamage"] == true)

-- jetpack detection through the glue (weapon id 46)
restart()
local r = Mock.newPlayer("carol")
Mock.settick(1000); Mock.tickTimers()
Mock.settick(1500); r.weapon = 46
Mock.tickTimers()
check("JETPACK finding surfaces through poll timer", Mock.logContains("JETPACK"), table.concat(Mock.log, " | "))

-- quit clears tracked state (no leak, no stale findings)
Mock.fire("onPlayerQuit", r)
Mock.settick(2000); r.money = 99999999; Mock.tickTimers()
check("quit player is dropped from tracking", true) -- no crash + no stale row for that tick
local rowsAfter = 0
for i = 1, #Mock.dbRows do if Mock.dbRows[i].player == "carol" and Mock.dbRows[i].ts == 2000 then rowsAfter = rowsAfter + 1 end end
check("no post-quit findings recorded", rowsAfter == 0, rowsAfter)

print(string.format("== result: %d passed, %d failed ==", pass, fail))
if fail > 0 then error("integration tests failed") end
