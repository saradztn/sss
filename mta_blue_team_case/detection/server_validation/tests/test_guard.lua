-- ===========================================================================
-- test_guard.lua — unit tests for guard_logic.lua (pure logic, off-server)
-- Run: bash tests/run_tests.sh   (see run_tests.sh for the interpreter probe)
-- These tests validate the RECONSTRUCTED detection logic only. They are not
-- evidence about how the original sample behaves on a live MTA:SA server.
-- ===========================================================================

local here = ...
if not here or here == "" then here = "." end
local root = here

local function loadfile_rel(path)
    local f = assert(loadfile(path), "cannot load " .. path)
    return f()
end

local Guard = loadfile_rel(root .. "/nrth_guard/server/guard_logic.lua")

local pass, fail = 0, 0
local function check(name, cond, extra)
    if cond then
        pass = pass + 1
        print(string.format("  [PASS] %s", name))
    else
        fail = fail + 1
        print(string.format("  [FAIL] %s %s", name, extra and (":: " .. tostring(extra)) or ""))
    end
end

local function newGuard(over)
    local cfg = { pollMs = 500 }
    if over then for k, v in pairs(over) do cfg[k] = v end end
    return Guard.new(cfg)
end

local P = { name = "tester" }   -- opaque "player element" key

local function sample(t, over)
    local s = { tick = t, health = 100, armor = 0, money = 1000, weapon = 4, ammo = 30,
                x = 0, y = 0, z = 3, velocity = { 0, 0, 0 }, inVehicle = false, vehModel = 0,
                jetpack = false }
    if over then for k, v in pairs(over) do s[k] = v end end
    return s
end

local function hasRule(findings, rule)
    for i = 1, #(findings or {}) do
        if findings[i].rule == rule then return findings[i] end
    end
    return nil
end

print("== nrth_guard logic tests ==")

-- 1. baseline stability: a clean client must never raise findings
do
    local g = newGuard()
    g:reset(P, "join")
    g:observe(P, sample(0))
    local n = 0
    for t = 1, 40 do
        local f = g:observe(P, sample(t * 500, { x = t * 10, y = 0, z = 3, money = 1000 + t * 5 }))
        n = n + #f
    end
    check("clean player -> 0 findings", n == 0, "got " .. n)
    check("clean player -> score stays ~0", g:score(P) < 0.001, g:score(P))
end

-- 2. first sample only establishes a baseline
do
    local g = newGuard()
    g:reset(P, "join")
    local f = g:observe(P, sample(0, { health = 500, money = 99e9 }))
    check("first sample never flags (no prev reference)", #f == 0, #f)
end

-- 3. impossible health value + instant heal
do
    local g = newGuard()
    g:observe(P, sample(0))
    local f = g:observe(P, sample(500, { health = 199 }))
    check("HEALTH_ABOVE_MAX on health>100", hasRule(f, "HEALTH_ABOVE_MAX") ~= nil, f and f[1] and f[1].rule)
    g:observe(P, sample(1000, { health = 100 }))
    f = g:observe(P, sample(1500, { health = 34, money = 1000 }))
    check("damage down never flags heal rules", hasRule(f, "HEALTH_JUMP") == nil)
    f = g:observe(P, sample(2000, { health = 100 }))
    check("HEALTH_JUMP on 34 -> 100 in 0.5s without grant", hasRule(f, "HEALTH_JUMP") ~= nil, f and f[1] and f[1].rule)
end

-- 4. legit spawn heals are suppressed by the grant window
do
    local g = newGuard()
    g:observe(P, sample(0, { health = 20 }))
    g:grant(P, "spawn", 400); g:grant(P, "health", 400); g:grant(P, "armor", 400)
    local f = g:observe(P, sample(500, { health = 100 }))
    check("grant(spawn/health) suppresses HEALTH_JUMP", hasRule(f, "HEALTH_JUMP") == nil, f and f[1] and f[1].rule)
end

-- 5. money exploit shape
do
    local g = newGuard()
    g:observe(P, sample(0, { money = 1000 }))
    local f, action = g:observe(P, sample(500, { money = 2500000 }))
    local mf = hasRule(f, "MONEY_RATE")
    check("MONEY_RATE fires on +2.5M in 0.5s", mf ~= nil)
    check("MONEY_RATE severity is high", mf and mf.severity == "high")
    check("report_only policy never kicks", action == nil or action.kind ~= "kick", action and action.kind)
end

-- 6. money rate within budget stays quiet
do
    local g = newGuard({ moneyGainPerSec = 60 })
    g:observe(P, sample(0, { money = 1000 }))
    local f = g:observe(P, sample(1000, { money = 1050 }))
    check("normal reward (+50/s) is not flagged", hasRule(f, "MONEY_RATE") == nil)
end

-- 7. infinite ammo
do
    local g = newGuard()
    g:observe(P, sample(0, { ammo = 30 }))
    local f = g:observe(P, sample(500, { ammo = 9000 }))
    check("AMMO_RATE on ammo 30 -> 9000", hasRule(f, "AMMO_RATE") ~= nil)
    f = g:observe(P, sample(1000, { ammo = 60 }))
    check("AMMO_ABOVE_MAX/AMMO_RATE quiet after clamp back to 60", hasRule(f, "AMMO_RATE") == nil)
end

-- 8. click-warp / teleport
do
    local g = newGuard()
    g:observe(P, sample(0, { x = 0, y = 0, z = 3 }))
    local f = g:observe(P, sample(500, { x = 5000, y = 5000, z = 3 }))
    check("TRAVEL_RATE on 7071u in 0.5s", hasRule(f, "TRAVEL_RATE") ~= nil)
    g:reset(P, "admin teleport")
    f = g:observe(P, sample(1000, { x = 0, y = 0, z = 3 }))
    check("after admin reset, next sample is a baseline", #f == 0)
end

-- 9. airbreak / speed hack (+ exemptions)
do
    local g = newGuard({ maxVehicleVelocityUnits = 2.40, vehicleExemptModels = { [599] = true } })
    g:observe(P, sample(0))
    local f = g:observe(P, sample(500, { inVehicle = true, vehModel = 411, velocity = { 2.0, 0, 0 } }))
    check("VEHICLE_SPEED quiet at |v|=2.00 u/s (below 2.40)", hasRule(f, "VEHICLE_SPEED") == nil, f and f[1] and f[1].detail)
    f = g:observe(P, sample(1000, { inVehicle = true, vehModel = 411, velocity = { 9.0, 0, 0 } }))
    check("VEHICLE_SPEED flags |v|=9.00 u/s (airbreak shape)", hasRule(f, "VEHICLE_SPEED") ~= nil)
    f = g:observe(P, sample(1500, { inVehicle = true, vehModel = 599, velocity = { 30.0, 0, 0 } }))
    check("config-listed exempt model does not flag", hasRule(f, "VEHICLE_SPEED") == nil)
end

-- 10. jetpack
do
    local g = newGuard({ allowJetpack = false })
    g:observe(P, sample(0))
    local f = g:observe(P, sample(500, { weapon = 46, jetpack = true }))
    check("JETPACK flags weapon 46 without grant", hasRule(f, "JETPACK") ~= nil)
    g:reset(P, "rejoin"); g:observe(P, sample(1000))
    g:grant(P, "jetpack", 1400)
    f = g:observe(P, sample(1500, { weapon = 46, jetpack = true }))
    check("jetpack granted by server is allowed", hasRule(f, "JETPACK") == nil)
end

-- 11. godmode corroboration (needs the server damage ledger)
do
    local g = newGuard({ godmodeWindowMs = 6000, godmodeMinDamage = 40 })
    g:observe(P, sample(0, { health = 100 }))
    g:recordDamage(P, 55, 500)
    local f = g:observe(P, sample(1000, { health = 100 }))
    check("no godmode verdict before the window elapses", hasRule(f, "GODMODE") == nil)
    g:observe(P, sample(3000, { health = 100 }))
    g:observe(P, sample(5000, { health = 100 }))
    f = g:observe(P, sample(7000, { health = 100 }))
    check("GODMODE fires: 55 damage applied, health pinned", hasRule(f, "GODMODE") ~= nil)
    g:recordDamage(P, 55, 7500)
    f = g:observe(P, sample(8000, { health = 45 }))
    check("health actually dropping clears the godmode ledger", hasRule(f, "GODMODE") == nil)
end

-- 12. armor ceiling
do
    local g = newGuard()
    g:observe(P, sample(0, { armor = 0 }))
    local f = g:observe(P, sample(500, { armor = 250 }))
    check("ARMOR_JUMP/ceiling on armor 250", hasRule(f, "ARMOR_JUMP") ~= nil)
end

-- 13. sanction ladder + cooldowns with banPolicy="kick"
do
    local g = newGuard({ scoreKickThreshold = 3, scoreWarnThreshold = 1, banPolicy = "kick", sanctionCooldownMs = 60000 })
    g:observe(P, sample(0, { money = 1000 }))
    local _, action = g:observe(P, sample(500, { money = 500000, x = 9000 }))
    check("kick action produced once over threshold", action and action.kind == "kick", action and action.kind)
    local _, action2 = g:observe(P, sample(1000, { money = 1000000, x = 18000 }))
    check("kick cooldown blocks a second action", action2 == nil, tostring(action2 and action2.kind))
end

-- 14. robustness: garbage input must not throw
do
    local g = newGuard()
    g:observe(P, sample(0))
    local ok, f = pcall(function()
        return g:observe(P, sample(500, { health = "abc", armor = nil, x = 0 / 0, money = 1000 }))
    end)
    check("NaN/nil fields do not crash the engine", ok, f)
    ok = pcall(function() g:observe(P, sample(500, { health = nil, x = nil, y = nil, z = nil })) end)
    check("missing position does not crash TRAVEL_RATE", ok)
end

-- 15. summary helper
do
    local g = newGuard()
    g:observe(P, sample(0))
    local s = g:summary()
    check("summary reports 1 tracked player", s.players == 1, s.players)
end

print(string.format("== result: %d passed, %d failed ==", pass, fail))
if fail > 0 then error("guard logic tests failed") end
