-- ===========================================================================
-- mock_mta.lua — minimal MTA:SA server API stand-in for off-server testing
-- ===========================================================================
-- PURPOSE: exercise nrth_guard/server/main.lua's glue (event wiring, sampling,
-- logging, sanction ladder) without a live MTA server. Everything here is a
-- TEST DOUBLE — running this proves the resource's code paths behave as written,
-- and proves NOTHING about real MTA behaviour or about the original sample.
-- Any conclusion drawn from a live server still requires private_server_tests/.
-- ===========================================================================

Mock = {
    tick = 0,
    log = {},
    chat = {},
    kicks = {},
    dbRows = {},
    dbSql = {},
    handlers = {},
    events = {},
    timers = {},
    nextTimer = 1,
    players = {},
    root = { __root = true },
}

local function settick(t) Mock.tick = t end
Mock.settick = settick

function getRootElement() return Mock.root end
function isElement(el) return type(el) == "table" and (el.__player or el.__veh or el.__root) and true or false end
function getElementType(el) return el and el.__type or false end
function getElementsByType(t)
    local out = {}
    for i = 1, #Mock.players do
        if Mock.players[i].__type == t then out[#out + 1] = Mock.players[i] end
    end
    return out
end
function getPlayerName(el) return el and el.name or "?" end
function getTickCount() return Mock.tick end
function outputServerLog(line) Mock.log[#Mock.log + 1] = line end
function outputChatBox(line, el) Mock.chat[#Mock.chat + 1] = { line = line, to = el } end
function kickPlayer(el, fmt, ...) Mock.kicks[#Mock.kicks + 1] = { player = el, reason = string.format(fmt, ...) } end

function addEvent(name, sync) Mock.events[name] = sync and true or false end
function addEventHandler(name, root, fn) Mock.handlers[name] = Mock.handlers[name] or {}; Mock.handlers[name][#Mock.handlers[name] + 1] = fn end
function fire(name, el)
    local hs = Mock.handlers[name] or {}
    local old = _G.source
    _G.source = el
    for i = 1, #hs do hs[i]() end
    _G.source = old
end
Mock.fire = fire

function setTimer(fn, interval, times, ...)
    local id = Mock.nextTimer; Mock.nextTimer = id + 1
    Mock.timers[id] = { fn = fn, interval = interval, times = times, calls = 0 }
    return id
end
function killTimer(id) Mock.timers[id] = nil end
function tickTimers()
    for id, t in pairs(Mock.timers) do
        t.calls = t.calls + 1
        t.fn()
    end
end
Mock.tickTimers = tickTimers

-- element state accessors -------------------------------------------------
function getElementHealth(el) return el.health end
function getPedArmor(el) return el.armor end
function getPlayerMoney(el) return el.money end
function getPedWeapon(el) return el.weapon end
function getPedAmmunition(el) return el.ammo end
function getElementPosition(el) return el.x, el.y, el.z end
function getElementVelocity(el) return el.vx or 0, el.vy or 0, el.vz or 0 end
function getElementModel(el) return el.model or 0 end
function isPedInVehicle(el) return el.inVehicle and true or false end
function getPedVehicleUsed(el) return el.vehicle or nil end

-- database ---------------------------------------------------------------
function dbConnect(kind, path) return { __db = true, kind = kind, path = path } end
function dbQuery(db, sql, ...)
    Mock.dbSql[#Mock.dbSql + 1] = sql
    if sql:match("^INSERT") then
        local row = { ts = select(1, ...), kind = select(2, ...), player = select(3, ...),
                      rule = select(4, ...), severity = select(5, ...), detail = select(6, ...),
                      score = select(7, ...) }
        Mock.dbRows[#Mock.dbRows + 1] = row
    end
    return { __result = true }
end
function dbFree(_) end
function dbPoll(_) return 0, 0 end

function newPlayer(name, over)
    local p = { __player = true, __type = "player", name = name,
                health = 100, armor = 0, money = 1000, weapon = 4, ammo = 30,
                x = 0, y = 0, z = 3, vx = 0, vy = 0, vz = 0, inVehicle = false }
    if over then for k, v in pairs(over) do p[k] = v end end
    Mock.players[#Mock.players + 1] = p
    return p
end
Mock.newPlayer = newPlayer

function resetMock()
    Mock.tick, Mock.log, Mock.chat, Mock.kicks, Mock.dbRows, Mock.dbSql = 0, {}, {}, {}, {}, {}
    Mock.timers, Mock.nextTimer, Mock.players = {}, 1, {}
end
Mock.reset = resetMock

function logContains(substr)
    for i = 1, #Mock.log do if Mock.log[i]:find(substr, 1, true) then return true end end
    return false
end
Mock.logContains = logContains
