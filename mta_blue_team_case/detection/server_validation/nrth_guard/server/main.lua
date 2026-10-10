-- ===========================================================================
-- main.lua — MTA:SA server glue for nrth_guard (defensive resource)
-- Case: mta_blue_team_case · Result class: R2
-- ===========================================================================
-- Attaches guard_logic.lua to live server state. Sampling is SERVER-SIDE ONLY:
-- it reads engine-replicated state (health/armor/money/position/velocity), so it
-- works whatever client-side mechanism produced the value (Lua-VM exec, memory
-- write, or netcode abuse). No client-side file is shipped by design — client
-- trust is exactly what the NORTH family bypasses.
--
-- MTA API surface used (verify against YOUR server build before deploying;
-- nothing here has been executed against a live MTA server in this engagement):
--   addEventHandler, setTimer, getTickCount, getRootElement, getPlayersInRadius? (not used)
--   getElementsByType("player"), isElement, getElementType
--   getElementHealth, getPedArmor, getPedWeapon, getPedAmmunition, getPlayerMoney,
--   getElementPosition, getElementVelocity, getElementModel, isPedInVehicle
--   getPlayerName, getPlayerSerial?, kickPlayer, outputServerLog, outputChatBox
--   dbConnect/dbQuery/dbFree (SQLite), onResourceStart, onPlayerJoin, onPlayerQuit,
--   onPlayerSpawn, onPlayerWasted, onPlayerVehicleEnter, onPlayerVehicleExit
-- ===========================================================================

-- Both files are listed in meta.xml and share the resource's single Lua VM,
-- so guard_logic.lua exposes itself as the global `GuardLogic` (idiomatic MTA;
-- no reliance on `require`/package paths).
local Guard = GuardLogic
local Config = GuardConfig

local guard = Guard.new(Config.values)
local db = nil
local pollTimer = nil

-- ---------------------------------------------------------------------------
-- Logging (SQLite + server console). Never logs credentials.
-- ---------------------------------------------------------------------------
local function logEvent(kind, player, finding)
    local name = (player and isElement(player) and getPlayerName(player)) or "?"
    local line = string.format("[nrth_guard] %s %s :: %s :: %s [score=%.1f]",
        kind, name, finding.rule or "-", finding.detail or "-", finding.score or 0)
    if outputServerLog then outputServerLog(line) end
    if db then
        dbQuery(db, "INSERT INTO events (ts, kind, player, rule, severity, detail, score) VALUES (?,?,?,?,?,?,?)",
            getTickCount(), kind, name, tostring(finding.rule), tostring(finding.severity),
            tostring(finding.detail), tonumber(finding.score) or 0)
    end
end

local function openDb()
    if dbConnect then
        db = dbConnect("sqlite", "nrth_guard.db")
        if db then
            dbQuery(db, [[CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, kind TEXT,
                player TEXT, rule TEXT, severity TEXT, detail TEXT, score REAL)]])
        end
    end
    return db
end

-- ---------------------------------------------------------------------------
-- Sampling
-- ---------------------------------------------------------------------------
local function buildSample(player, tick)
    local s = { tick = tick }
    s.health = getElementHealth(player)
    s.armor  = getPedArmor and getPedArmor(player) or 0
    s.money  = getPlayerMoney(player)
    s.weapon = getPedWeapon and getPedWeapon(player) or -1
    s.ammo   = getPedAmmunition and getPedAmmunition(player) or 0
    local x, y, z = getElementPosition(player)
    s.x, s.y, s.z = x, y, z
    local vx, vy, vz = 0, 0, 0
    if getElementVelocity then vx, vy, vz = getElementVelocity(player) end
    s.velocity = { vx, vy, vz }
    local inVeh = isPedInVehicle and isPedInVehicle(player) or false
    s.inVehicle = inVeh and true or false
    s.vehModel  = 0
    if s.inVehicle and getPedVehicleUsed then
        local v = getPedVehicleUsed(player)
        if v and isElement(v) then s.vehModel = getElementModel(v) end
    end
    s.jetpack = false
    return s
end

local function pollAll()
    local tick = getTickCount()
    for _, player in ipairs(getElementsByType("player")) do
        if isElement(player) then
            local findings, action = guard:observe(player, buildSample(player, tick))
            for i = 1, #findings do
                logEvent("FINDING", player, findings[i])
            end
            if action then
                logEvent("ACTION:" .. action.kind, player,
                         { rule = "LADDER", detail = "score " .. string.format("%.1f", action.score) })
                applySanction(player, action)
            end
        end
    end
end

-- ---------------------------------------------------------------------------
-- Legit grants (suppress false positives on legitimate state changes)
-- ---------------------------------------------------------------------------
local function grantFor(player, kind)
    guard:grant(player, kind, getTickCount())
end

addEventHandler("onResourceStart", getRootElement(), function()
    openDb()
    for _, player in ipairs(getElementsByType("player")) do
        guard:reset(player, "resource start")
    end
    if not pollTimer then
        pollTimer = setTimer(pollAll, Config.values.pollMs, 0)
    end
    outputServerLog("[nrth_guard] started · policy=" .. tostring(Config.values.banPolicy) ..
                    " · poll=" .. tostring(Config.values.pollMs) .. "ms")
end)

addEventHandler("onResourceStop", getRootElement(), function()
    if pollTimer then killTimer(pollTimer); pollTimer = nil end
end)

addEventHandler("onPlayerJoin", getRootElement(), function()
    guard:reset(source, "join")
end)

addEventHandler("onPlayerQuit", getRootElement(), function()
    guard.players[source] = nil
    guard.grants[source] = nil
end)

-- Spawn / respawn legitimately restores health+armor: open a grant window so
-- the HEALTH_JUMP / ARMOR_JUMP / RESPAWN_HEAL rules do not fire on it.
addEventHandler("onPlayerSpawn", getRootElement(), function()
    local tick = getTickCount()
    guard:grant(source, "health", tick)
    guard:grant(source, "armor", tick)
    guard:grant(source, "spawn", tick)
end)

addEventHandler("onPlayerWasted", getRootElement(), function()
    guard:recordDamage(source, 100, getTickCount())
    guard:reset(source, "wasted")
end)

-- If your gamemode (or a damage resource) knows damage was applied, report it —
-- that is what makes the GODMODE corroboration rule possible at all.
addEvent("nrthGuard:serverDamage", true)
addEventHandler("nrthGuard:serverDamage", getRootElement(), function(amount)
    if isElement(source) then guard:recordDamage(source, tonumber(amount) or 0, getTickCount()) end
end)

-- Custom currency / admin gives: call grantFor(player, "money") from your code.
addEvent("nrthGuard:grant", true)
addEventHandler("nrthGuard:grant", getRootElement(), function(kind)
    if isElement(source) and type(kind) == "string" then grantFor(source, kind) end
end)

-- Sanctions stay opt-in. "kick" only fires when banPolicy == "kick".
function applySanction(player, action)
    if not player or not isElement(player) then return end
    if action.kind == "report" or action.kind == "log" then return end   -- server-side record only
    if action.kind == "warn" then
        outputChatBox("[Guard] anomalous client state logged. You are being monitored.", player, 255, 180, 0)
    elseif action.kind == "kick" then
        kickPlayer(player, "nrth_guard: impossible client state (score %.1f)", action.score)
    end
end
