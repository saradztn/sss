--[[ nrth_acwatch — server-side anti-cheat report watcher for the NRTH case (v1).

    WHY THIS MEASURES SILENCE
    The sample's netc.dll cluster ends in six one-byte 0xC3 writes over the *loaded* report functions
    (staging `mov byte ptr [ebp-disp8],0xC3` 11 bytes before each `call` at 0x100206f0 / 0x100208aa /
    0x10020927 / 0x10020f46 / 0x100214bd / 0x100215f1, applied through
    VirtualProtect(page,1,PAGE_EXECUTE_READWRITE) at 0x10011870, target list 0x101493e4).
    A ret-immediately entry returns before the screenshot/transgression payload is built, so the
    server stops receiving that client's reports while the player keeps playing normally.
    Confidence: Strongly inferred for the mechanism (bytes measured in the sample), Unknown for exact
    per-event loss ordering. This resource only *counts arrivals* — it changes nothing on clients.

    EVENT NAMES
    The sample's own string table carries PACKET_ID_PLAYER_SCREENSHOT / _TRANSGRESSION / _DIAGNOSTIC /
    _ACINFO (measured: .rdata 0x100eb6a8 and neighbours) — those are internal packet ids, NOT Lua
    events. The Lua-visible AC surface used here is onPlayerACInfo / onPlayerScreenshot /
    onPlayerModInfo. Verify the three names against your server build (mta wiki for your version);
    a wrong name is not silently ignored here — the heartbeat below reports "watch never fired".

    Output (in this resource's directory):
      ac_report_counter.csv    one row per (player, window)
      ac_report_alerts.log     silence + heartbeat findings, human readable, timestamped
      ac_report_state.json     last window snapshot, for the offline tooling
--]]

local EVENTS = {
    acinfo     = "onPlayerACInfo",
    screenshot = "onPlayerScreenshot",
    modinfo    = "onPlayerModInfo",
}

local WINDOW_MS   = 60000     -- one row per player per minute
local SILENT_MS   = 120000    -- online this long with zero AC events -> alert
local DIR         = "cfg/"    -- resource-relative; getAbsoluteResourcePath is used for the real path

local stats       = {}        -- [playerSerial] = {name=..., join=..., c={acinfo=0,...}, fired=0}
local windowFired = 0         -- AC events seen since the last window (any player)
local totalFired  = 0

local function serial(p) return getPlayerSerial(p) end

local function now() return getRealTime().timestamp end

local function fmtKey(p)
    return (p and (getPlayerName(p) .. "|" .. serial(p))) or "left"
end

local function bump(p, key)
    local s = serial(p)
    local e = stats[s]
    if not e then
        e = { name = getPlayerName(p), join = now(), c = { acinfo = 0, screenshot = 0, modinfo = 0 } }
        stats[s] = e
    end
    if key and e.c[key] then e.c[key] = e.c[key] + 1 end
    windowFired = windowFired + 1
    totalFired  = totalFired + 1
end

for key, evName in pairs(EVENTS) do
    -- 'p' is the player element for all three events in MTA's server-side signature.
    addEventHandler(function(p) if p and type(p) == "player" then bump(p, key) end end, root, evName)
end

addEventHandler(function()
    local p = source
    stats[serial(p)] = { name = getPlayerName(p), join = now(), c = { acinfo = 0, screenshot = 0, modinfo = 0 } }
end, root, "onPlayerJoin")

local function snapshot(p)
    return stats[serial(p)]
end

-- flush(): write the window's rows, then reset per-window counters and raise alerts.
local function flush()
    local t = now()
    local csv = io.open(getAbsoluteResourcePath(getThisResource()) .. "/" .. DIR .. "ac_report_counter.csv", "a")
    local log = io.open(getAbsoluteResourcePath(getThisResource()) .. "/" .. DIR .. "ac_report_alerts.log", "a")
    if csv then
        csv:write("utc,player,serial,acinfo,screenshot,modinfo,online_s\n")
    end
    local silent = {}
    for s, e in pairs(stats) do
        local online = t - (e.join or t)
        local tot = e.c.acinfo + e.c.screenshot + e.c.modinfo
        if csv then
            csv:write(string.format("%d,%s,%s,%d,%d,%d,%d\n", t, (e.name or ""):gsub(",", ";"), s,
                e.c.acinfo, e.c.screenshot, e.c.modinfo, online))
        end
        if online >= (SILENT_MS / 1000) and tot == 0 then
            silent[#silent + 1] = string.format("%s (%s) online %ds with ZERO AC-report events",
                e.name or "?", s, online)
        end
        e.c.acinfo, e.c.screenshot, e.c.modinfo = 0, 0, 0
    end
    if csv then csv:close() end
    local hb = ""
    if totalFired == 0 then
        hb = "HEARTBEAT: no AC event was ever received by this resource - the three event names in "
          .. "EVENTS do not match this server build, or no player has connected. Fix the names before "
          .. "trusting a 'clean' verdict."
    end
    if log then
        if #silent > 0 then
            for i = 1, #silent do
                log:write(string.format("[%d] SILENCE %s\n", t, silent[i]))
            end
        end
        if hb ~= "" then log:write(string.format("[%d] %s\n", t, hb)) end
        log:close()
    end
    local js = io.open(getAbsoluteResourcePath(getThisResource()) .. "/" .. DIR .. "ac_report_state.json", "w")
    if js then
        js:write(string.format('{"utc":%d,"window_fired":%d,"total_fired":%d,"players":%d,"silent":%d%s}\n',
            t, windowFired, totalFired, (function() local n = 0 for _ in pairs(stats) do n = n + 1 end return n end)(),
            #silent, hb ~= "" and ',"watch_heartbeat":"no AC events ever received"' or ''))
        js:close()
    end
    if hb ~= "" then outputLogString("nrth_acwatch: " .. hb) end
    windowFired = 0
end

setTimer(flush, WINDOW_MS, 0)

addEventHandler(function()
    local p, s = source, serial(source)
    local e = snapshot(p)
    if e then
        local tot = e.c.acinfo + e.c.screenshot + e.c.modinfo
        local log = io.open(getAbsoluteResourcePath(getThisResource()) .. "/" .. DIR .. "ac_report_alerts.log", "a")
        if log then
            log:write(string.format("[%d] QUIT %s events=%d %s\n", now(), fmtKey(p), tot,
                tot == 0 and "(silent session - correlate with client collector)" or ""))
            log:close()
        end
        stats[s] = nil
    end
end, root, "onPlayerQuit")

addEventHandler(function() flush() end, root, "onResourceStop")

outputLogString("nrth_acwatch: watching " .. EVENTS.acinfo .. ", " .. EVENTS.screenshot .. ", "
    .. EVENTS.modinfo .. " | window " .. (WINDOW_MS / 1000) .. "s | silence alert after "
    .. (SILENT_MS / 1000) .. "s online")
