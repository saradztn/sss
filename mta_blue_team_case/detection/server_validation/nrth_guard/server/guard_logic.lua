-- ===========================================================================
-- guard_logic.lua — MTA:SA server-side validation engine (defensive)
-- Case: mta_blue_team_case · Result class: R2 (newly authored, evidence-driven)
-- ===========================================================================
-- WHY THIS FILE EXISTS
--   mechanism_overview_ar.md §8.2 concludes that validating impossible values
--   server-side neutralises most of the NORTH/NRTH feature set regardless of
--   how the client achieves it (Lua-VM exec, memory writes, or netcode).
--   This engine implements that control. It deliberately does NOT require any
--   client-side trust and contains no client instrumentation.
--
-- TARGET: MTA:SA server Lua (Lua 5.1 semantics: no goto, no integer division,
--         no bit ops, no table.unpack). Pure logic — zero MTA API calls, so it
--         is unit-testable off-server (see ../../tests/test_guard.lua).
--
-- FALSE-POSITIVE POLICY: every rule is advisory by default. `banPolicy`
--   defaults to "report_only". Thresholds MUST be calibrated against a clean
--   baseline run (private_server_tests/test_plan.md T0) before any sanction.
-- ===========================================================================

local Guard = {}

Guard.DEFAULTS = {
    -- Absolute impossible-state ceilings
    maxHealth              = 100.0,
    maxArmor               = 100.0,
    maxMoney               = 2000000000,
    maxAmmoPerWeapon       = 500,      -- SA reserves are far below this per weapon

    -- Rate ceilings (per second). Calibrate on baseline T0.
    healthGainPerSec       = 0.60,     -- covers slow passive regen + brief pickups
    armorGainPerSec        = 12.0,     -- armour body pickup is a one-shot jump
    moneyGainPerSec        = 60.0,     -- legit mission rewards are bursty: keep generous
    ammoGainPerSec         = 40.0,
    weaponGrantsPerSec     = 1.0,

    -- Movement
    maxTravelUnitsPerSec   = 260.0,    -- distance/dt ceiling (instant-travel / click warp)
    -- In-game velocity is compared in RAW game units/s (|getElementVelocity|), because a
    -- km/h conversion factor was not measured on the team's build. Starting point only:
    -- calibrate maxVehicleVelocityUnits from baseline T0 (p99.9) before enabling sanctions.
    maxVehicleVelocityUnits = 2.40,
    vehicleExemptModels    = {},       -- fill from YOUR server's vehicle ids (getElementModel); none verified here

    -- GodMode / heal abuse
    godmodeWindowMs        = 6000,
    godmodeMinDamage       = 40.0,
    respawnMinMs           = 350,      -- heal faster than this right after damage = suspicious

    -- Jetpack
    allowJetpack           = false,

    -- Grant suppression: a server-side grant clears the matching rule window
    grantWindowMs          = 2500,

    -- Scoring / sanctions
    scoreKickThreshold     = 12.0,
    scoreWarnThreshold     = 4.0,
    scoreDecayPerSec       = 0.02,
    sanctionCooldownMs     = 60000,
    banPolicy              = "report_only",  -- report_only | log | warn | kick
}

local function shallowcopy(src)
    local out = {}
    for k, v in pairs(src) do out[k] = v end
    return out
end

local function num(v)
    if type(v) ~= "number" then return nil end
    if v ~= v then return nil end -- NaN
    return v
end

local function clampPos(v)
    if type(v) ~= "number" or v ~= v then return 0 end -- NaN guard
    if v < 0 then return 0 end
    return v
end

-- ---------------------------------------------------------------------------
-- Instance
-- ---------------------------------------------------------------------------
function Guard.new(userConfig)
    local self = {}
    local cfg = shallowcopy(Guard.DEFAULTS)
    if userConfig then
        for k, v in pairs(userConfig) do cfg[k] = v end
    end
    self.cfg     = cfg
    self.players = {}     -- key -> player state
    self.grants  = {}     -- key -> { kind = tick }
    return setmetatable(self, { __index = Guard })
end

function Guard._state(self, key)
    local p = self.players[key]
    if not p then
        p = { score = 0.0, lastTick = nil, samples = 0, dmg = 0.0, dmgStart = nil,
              lastWarn = nil, lastAct = nil }
        self.players[key] = p
    end
    return p
end

-- Re-baseline a player (spawn/respawn/join/teleport-by-admin): the next sample
-- becomes the reference and no rule can fire on the transition itself.
function Guard.reset(self, key, reason)
    self.players[key] = nil
    return { rule = "RESET", severity = "info", score = 0,
             detail = "baseline cleared (" .. tostring(reason) .. ")" }
end

-- Record a legitimate server-side grant (reward, pickup handler, admin give)
-- so that the corresponding jump is not treated as a cheat.
function Guard.grant(self, key, kind, tick)
    local g = self.grants[key]
    if not g then g = {}; self.grants[key] = g end
    g[kind] = tick
end

function Guard._recentlyGranted(self, key, kind, tick, windowMs)
    local g = self.grants[key]
    if not g or not g[kind] then return false end
    local window = windowMs or self.cfg.grantWindowMs
    return (tick - g[kind]) <= window
end

-- The server (or another resource) tells us damage was applied to this player.
-- Used only for the GodMode corroboration rule: health that never moves while
-- the server applied real damage is the signature of a client-side invincibility.
function Guard.recordDamage(self, key, amount, tick)
    amount = tonumber(amount) or 0
    if amount <= 0 then return end
    local p = self._state(self, key)
    p.dmg = p.dmg + amount
    if not p.dmgStart then p.dmgStart = tick end
end

function Guard.score(self, key)
    local p = self.players[key]
    return p and p.score or 0.0
end

-- ---------------------------------------------------------------------------
-- Observation
--   sample = { tick, health, armor, money, weapon, ammo, x, y, z,
--              inVehicle, vehModel, velocity = {x,y,z}, jetpack }
--   returns a list of findings (possibly empty)
-- ---------------------------------------------------------------------------
local RULES = {}

RULES.HEALTH_ABOVE_MAX = function(self, p, s, dt, prev)
    local h = tonumber(s.health)
    if not h then return nil end
    if h > self.cfg.maxHealth + 0.001 then
        return { severity = "high",
                 detail = string.format("health %.1f > ceiling %.1f", h, self.cfg.maxHealth),
                 evidence = "getElementHealth"}
    end
    return nil
end

RULES.HEALTH_JUMP = function(self, p, s, dt, prev)
    local h, ph = tonumber(s.health), tonumber(prev and prev.health)
    if not h or not ph then return nil end
    local gain = h - ph
    if gain <= 0 then return nil end
    if self:_recentlyGranted(s.key, "health", s.tick) then return nil end
    local allowed = self.cfg.healthGainPerSec * dt + 0.5
    if gain > allowed then
        return { severity = "medium",
                 detail = string.format("health +%0.1f in %0.2fs (allowed %0.1f)",
                                        gain, dt, allowed),
                 evidence = "delta(health) between server polls"}
    end
    return nil
end

RULES.ARMOR_JUMP = function(self, p, s, dt, prev)
    local a, pa = tonumber(s.armor), tonumber(prev and prev.armor)
    if not a then return nil end
    if a > self.cfg.maxArmor + 0.001 then
        return { severity = "medium", detail = string.format("armor %.1f > ceiling %.1f", a, self.cfg.maxArmor),
                 evidence = "getPedArmor" }
    end
    if not pa then return nil end
    local gain = a - pa
    if gain <= 0 then return nil end
    if self:_recentlyGranted(s.key, "armor", s.tick) then return nil end
    local allowed = self.cfg.armorGainPerSec * dt + 1
    if gain > allowed then
        return { severity = "medium",
                 detail = string.format("armor +%0.1f in %0.2fs (allowed %0.1f)", gain, dt, allowed),
                 evidence = "delta(armor) between server polls"}
    end
    return nil
end

RULES.MONEY_RATE = function(self, p, s, dt, prev)
    local m, pm = tonumber(s.money), tonumber(prev and prev.money)
    if not m or not pm then return nil end
    if m > self.cfg.maxMoney then
        return { severity = "high", detail = string.format("money %d above protocol ceiling", m),
                 evidence = "getPlayerMoney" }
    end
    local gain = m - pm
    if gain <= 0 then return nil end
    if self:_recentlyGranted(s.key, "money", s.tick) then return nil end
    local allowed = self.cfg.moneyGainPerSec * dt + 1
    if gain > allowed then
        return { severity = "high",
                 detail = string.format("money +%d in %0.2fs (allowed %0.1f) — money-exploit shape",
                                        gain, dt, allowed),
                 evidence = "delta(money) between server polls"}
    end
    return nil
end

RULES.AMMO_RATE = function(self, p, s, dt, prev)
    local a, pa = tonumber(s.ammo), tonumber(prev and prev.ammo)
    if not a or not pa then return nil end
    if self:_recentlyGranted(s.key, "ammo", s.tick) then return nil end
    local allowed = self.cfg.ammoGainPerSec * dt + 1
    if (a - pa) > allowed then
        return { severity = "medium",
                 detail = string.format("ammo +%d in %0.2fs (allowed %0.1f) — infinite-ammo shape",
                                        a - pa, dt, allowed),
                 evidence = "delta(getPedAmmunition)"}
    end
    if a > self.cfg.maxAmmoPerWeapon then
        return { severity = "low", detail = string.format("ammo reserve %d exceeds %.0f", a, self.cfg.maxAmmoPerWeapon),
                 evidence = "getPedAmmunition" }
    end
    return nil
end

RULES.TRAVEL_RATE = function(self, p, s, dt, prev)
    if not prev or not prev.x then return nil end
    local dx, dy, dz = s.x - prev.x, s.y - prev.y, s.z - prev.z
    local dist = math.sqrt(dx * dx + dy * dy + dz * dz)
    local speed = dist / dt
    if speed > self.cfg.maxTravelUnitsPerSec then
        return { severity = "high",
                 detail = string.format("implied travel %.0f u/s over %.2fs (dist %.0f) — click-warp/teleport shape",
                                        speed, dt, dist),
                 evidence = "delta(getElementPosition)/dt"}
    end
    return nil
end

RULES.VEHICLE_SPEED = function(self, p, s, dt, prev)
    if not s.inVehicle then return nil end
    if self.cfg.vehicleExemptModels[s.vehModel] then return nil end
    local v = s.velocity or {}
    local vx, vy, vz = num(v[1]) or 0, num(v[2]) or 0, num(v[3]) or 0
    local mag = math.sqrt(vx * vx + vy * vy + vz * vz)   -- |getElementVelocity|, game units/s
    if mag > self.cfg.maxVehicleVelocityUnits then
        return { severity = "medium",
                 detail = string.format("vehicle |velocity| %.2f u/s > %.2f — airbreak/speed shape",
                                        mag, self.cfg.maxVehicleVelocityUnits),
                 evidence = "|getElementVelocity| between server polls (units/s; calibrate on T0)"}
    end
    return nil
end

RULES.JETPACK = function(self, p, s, dt, prev)
    if self.cfg.allowJetpack then return nil end
    local flagged = s.jetpack and true or false
    if tonumber(s.weapon) == 46 then flagged = true end -- weapon id 46 = jetpack
    if not flagged then return nil end
    if self:_recentlyGranted(s.key, "jetpack", s.tick) then return nil end
    return { severity = "high", detail = "jetpack active without server grant",
             evidence = "getPedWeapon==46 / ped config flag" }
end

RULES.GODMODE = function(self, p, s, dt, prev)
    if not p.dmgStart then return nil end
    local held = s.tick - p.dmgStart
    if held < self.cfg.godmodeWindowMs then return nil end
    if p.dmg < self.cfg.godmodeMinDamage then return nil end
    local h0 = tonumber(prev and prev.health) or tonumber(s.health)
    if math.abs((tonumber(s.health) or 0) - (h0 or 0)) > 0.5 then
        p.dmg, p.dmgStart = 0.0, nil
        return nil
    end
    local f = { severity = "high",
                detail = string.format("health unchanged at %0.1f while server applied %0.1f damage over %.1fs — godmode shape",
                                       tonumber(s.health) or 0, p.dmg, held / 1000),
                evidence = "recordDamage() ledger vs delta(health)"}
    p.dmg, p.dmgStart = 0.0, nil
    return f
end

RULES.RESPAWN_HEAL = function(self, p, s, dt, prev)
    if not prev or not prev.hurtTick then return nil end
    local h, ph = tonumber(s.health) or 0, tonumber(prev.health) or 0
    if h > ph and (s.tick - prev.hurtTick) < self.cfg.respawnMinMs and self:_recentlyGranted(s.key, "spawn", s.tick) == false then
        return { severity = "low",
                 detail = string.format("health %.0f -> %.0f %.0fms after damage (respawn grace %dms)",
                                        ph, h, s.tick - prev.hurtTick, self.cfg.respawnMinMs),
                 evidence = "delta(health) vs last damage timestamp"}
    end
    return nil
end

local SEVERITY_WEIGHT = { high = 3.0, medium = 1.5, low = 0.5, info = 0.0 }

function Guard.observe(self, key, s)
    assert(s and s.tick, "sample.tick required")
    local cfg = self.cfg
    local p = self._state(self, key)
    local findings = {}
    local prev = p.last
    local dt
    if prev and prev.tick then
        dt = (s.tick - prev.tick) / 1000.0
        if dt <= 0 then dt = 0.001 end
    else
        dt = nil
    end

    -- score decay
    if prev and prev.tick then
        p.score = clampPos(p.score - (s.tick - prev.tick) / 1000.0 * cfg.scoreDecayPerSec)
    end

    s.key = key
    s.hurtTick = prev and prev.hurtTick or nil
    local hNow, hPrev = num(s.health), num(prev and prev.health)
    if hNow and hPrev and hNow < hPrev then
        s.hurtTick = s.tick
    end

    if dt then -- first sample only establishes a baseline; never flags
        for name, fn in pairs(RULES) do
            local ok, f = pcall(fn, self, p, s, dt, prev)
            if ok and f then
                f.rule = name
                f.tick = s.tick
                local w = SEVERITY_WEIGHT[f.severity] or 1.0
                f.score = w
                p.score = p.score + w
                findings[#findings + 1] = f
            elseif not ok then
                findings[#findings + 1] = { rule = name, severity = "error", score = 0,
                                            detail = "rule raised: " .. tostring(f) }
            end
        end
    end

    p.last = s
    p.samples = p.samples + 1

    return self:_decideAction(key, p, s.tick, findings)
end

-- ---------------------------------------------------------------------------
-- Sanction ladder. NEVER auto-punishes by default (banPolicy = "report_only").
-- ---------------------------------------------------------------------------
function Guard._decideAction(self, key, p, tick, findings)
    local cfg = self.cfg
    local action = nil
    if p.score >= cfg.scoreWarnThreshold then
        if p.lastWarn == nil or (tick - p.lastWarn) >= cfg.sanctionCooldownMs then
            p.lastWarn = tick
            local kind = "warn"
            if cfg.banPolicy == "report_only" or cfg.banPolicy == "log" then
                kind = cfg.banPolicy            -- never talk to the player under report_only/log
            end
            action = { kind = kind, score = p.score }
        end
    end
    if p.score >= cfg.scoreKickThreshold and cfg.banPolicy == "kick" then
        if p.lastAct == nil or (tick - p.lastAct) >= cfg.sanctionCooldownMs then
            p.lastAct = tick
            action = { kind = "kick", score = p.score }
        end
    end
    return findings, action
end

-- Convenience for tests/tools: total score across all players.
function Guard.summary(self)
    local n, total = 0, 0.0
    for k, p in pairs(self.players) do
        n = n + 1
        total = total + p.score
    end
    return { players = n, totalScore = total }
end

_G.GuardLogic = Guard   -- MTA: same-VM global (meta.xml loads files in order); `return` keeps it unit-testable off-server
return Guard
