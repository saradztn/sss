/**
 * ============================================================================
 * nrth_ui.cpp — UI reconstruction of the REAL "North Cheat" menu (R2)
 * ============================================================================
 * Evidence sources (see analysis/strings_catalog.txt + runtime screenshot):
 *   - Window title "North Cheat"                         (VA 0x1000e90d8)
 *   - Top tabs  "%s##nvx_top_%d"  -> Scripts | Dumper | Cheat | Vehicle | Config
 *     labels: "Scripts" 0xe9480, "Dumper" 0xe8588*, "Cheat" 0xe94a0,
 *             "Vehicle" 0xe9498, "Config" 0xe91bc  (*also a vehicle name)
 *   - Scripts sub-tabs "%s##nvx_ssub_%d" -> Editor | Scripts | Resources |
 *             Events | Events Table | Packets   (0xe94a8-0xe94dc)
 *   - Cheat sub-tabs  "%s##nvx_csub_%d"  -> Player | Other | Markers (0xe94ec-0xe950c)
 *   - Editor: "##lua_editor", "Default VM" 0xe9884, "@custom" 0xe9890,
 *             "Execute" 0xe9898, "Script executed" 0xe98b8
 *   - Scripts: "\\lua\\*.*" 0xe985c, "%s\\lua\\%s" 0xe9868, "##scripts_list",
 *             "Inject##%d", "Auto-inj##%d", "Injected: %s", "Dump", "Dump all",
 *             "Dump all scripts saved (%d)", "Dump script saved: %s",
 *             "File big, no view script", "Select script...", "No scripts found"
 *   - Resources/Events: "Select Resource" "Stop Resource" "Resource stopped: %s",
 *             " (blocked)", "Block##event" "Event blocked: %s" "Select Event",
 *             "##trigger_input" "Add to Block List" "Unblock##event",
 *             "Recent Triggers:" "No triggers"
 *   - Packets: "Search packet..." "##packet_search" "Refresh" "Packets: %zu"
 *             "Clear All" "Unblock All" "No packets detected." "Name: %s"
 *             "Time: %s" "ID: %d" "BLOCKED"/"UNBLOCKED" "Block Packet"
 *             "Resend" "Resending packet: %s" "Copy Name" "Select a packet"
 *             + full MTA PACKET_ID_* table (0xe9be4-0xeaaa4)
 *   - Player: " (you)" "No players found" "##player_combo" "##player_filter"
 *             "Teleport" "Bomb" "Add Friend" "Delete Friend" "Friend's list"
 *             "No friends added" "%s (%.1f, %.1f, %.1f)"
 *   - Cheat features (0xe8e08-0xe8f2c settings, 0xe8fa4-0xe9098 toggles):
 *             GodMode, Give HP, Give Armor, Infinite Ammo, Anti-Spread,
 *             Anti-ScreenShot ("Hide obs/discord"), Crasher ("Crasher player"),
 *             Anti-AFK, AirBreak (Speed/Increment/Keybinds), Click Warp
 *             (Max Distance/Crosshair Size/Ground Warp/Enter Vehicle),
 *             High Jump, Money Exploit, Jetpack, All Weapons
 *   - Vehicle: "Vehicles List" "##vehicles_combo" "%s (HP: %.0f)" "Select vehicle..."
 *             "Teleport to Vehicle" "Teleport Vehicle" "Bomb Car",
 *             Vehicle GodMode/Chaos, Drive Water, Fast Stop, Fall Bike,
 *             Flying Car, Start Engine, Repair Car, Unlock Car (+ Settings)
 *             status: "Vehicle repaired" "Engine started" "Vehicle stopped"
 *             "Unlocked nearest vehicle" "Vehicle teleported to you" ...
 *   - Config: "Configs" "##cfgitem" "##cfg_right" "Save As..." "Load" "Delete"
 *             "Reset to Default" "Reset to default style" "OVRCFG" ".ovr" "\*.ovr"
 *             "Config saved/loaded/deleted: %s" "Watermark" "Notifications"
 *             "Menu Toggle Key" "Press..." "Keybind's" "##keybinds"
 *             "Bind: %s -> %s" "Bind cleared: %s" "Toggle"/"Hold"/"Press a key..."
 *   - Color editor: "Color Settings" "##picker" "##color_list" "##filter"
 *             "Search color..." "Reset Colors" "Colors reset" + ~30 color names
 *   - Status (screenshot): "No connected server."
 *   - Dumper tab: "Address: 0x" (0x916d) memory/class dump display
 *
 * CLASSIFICATION NOTE (truth policy):
 *   UI + local file/state handling = reconstructed behavior (R2).
 *   Game-memory mutation, netcode (packet block/resend), Lua-VM injection and
 *   griefing primitives in the original are NOT re-implemented here: they are
 *   active exploit/cheat behavior; the buttons show the original status
 *   messages but route through FeatureAction() which is an explicit stub.
 *   Their original internals remain class U / documented in the case report.
 * ============================================================================
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

#include "imgui.h"
#include "nrth_ui.h"
#include "nrth_vehicle_names.inc"

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
static int  s_topTab     = 0;   // 0 Scripts, 1 Dumper, 2 Cheat, 3 Vehicle, 4 Config
static int  s_scriptsSub = 0;   // Editor | Scripts | Resources | Events | Events Table | Packets
static int  s_cheatSub   = 0;   // Player | Other | Markers
static bool s_menuOpen   = true;

// Editor
static char s_editorBuf[65536] = "-- North Cheat editor (R2 UI reconstruction)\n";
static int  s_vmIndex     = 0;  // "Default VM", "@custom"

// Status line (original composes "No connected server." at runtime — screenshot)
static std::string s_status        = "No connected server.";
static std::string s_lastAction;

// Scripts (real local listing from .\lua\*.lua)
struct ScriptItem { std::string name; bool autoInject; };
static std::vector<ScriptItem> s_scripts;
static int  s_scriptSel = -1;
static bool s_scriptsScanned = false;

// Resources / Events / Packets (UI shells with recorded local state)
static std::vector<std::string> s_resources;
static std::vector<std::string> s_blockedEvents;
static std::vector<std::string> s_recentTriggers;
struct PacketRow { std::string name; int id; bool blocked; std::string time; };
static std::vector<PacketRow> s_packets;
static char s_packetSearch[64] = "";
static int  s_packetSel = -1;

// Players / friends / markers
struct PlayerRow { std::string name; bool isYou; };
static std::vector<PlayerRow> s_players;
static std::vector<std::string> s_friends;
static std::string s_playerFilter;
static int  s_playerSel = 0;
struct MarkerRow { std::string name; float x, y, z; };
static std::vector<MarkerRow> s_markers;
static char s_markerName[64] = "";

// Feature toggles (14 Cheat-Other + 9 Vehicle) — evidence 0xe8fa4-0xe9098
struct Feature { const char *label; const char *settings; bool on; int key; int mode; };
static Feature s_cheatFeatures[] = {
    {"GodMode",        "GodMode Settings",        false, 0, 1},
    {"Give HP",        "Give HP Settings",        false, 0, 1},
    {"Give Armor",     "Give Armor Settings",     false, 0, 1},
    {"Infinite Ammo",  "Infinite Ammo Settings",  false, 0, 1},
    {"Anti-Spread",    "Anti-Spread Settings",    false, 0, 1},
    {"Anti-ScreenShot","Anti-ScreenShot Settings",false, 0, 1},
    {"Crasher",        "Crasher Settings",        false, 0, 1},
    {"Anti-AFK",       "Anti-AFK Settings",       false, 0, 1},
    {"AirBreak",       "AirBreak Settings",       false, 0, 1},
    {"Click Warp",     "Click Warp Settings",     false, 0, 1},
    {"High Jump",      "High Jump Settings",      false, 0, 1},
    {"Money Exploit",  "Money Exploit Settings",  false, 0, 1},
    {"Jetpack",        "Jetpack Settings",        false, 0, 1},
    {"All Weapons",    "All Weapons Settings",    false, 0, 1},
};
static Feature s_vehicleFeatures[] = {
    {"Vehicle GodMode", "Vehicle GodMode Settings", false, 0, 1},
    {"Vehicle Chaos",   "Vehicle Chaos Settings",   false, 0, 1},
    {"Drive Water",     "Drive Water Settings",     false, 0, 1},
    {"Fast Stop",       "Fast Stop Settings",       false, 0, 1},
    {"Fall Bike",       "Fall Bike Settings",       false, 0, 1},
    {"Flying Car",      "Flying Car Settings",      false, 0, 1},
    {"Start Engine",    "Start Engine Settings",    false, 0, 1},
    {"Repair Car",      "Repair Car Settings",      false, 0, 1},
    {"Unlock Car",      "Unlock Car Settings",      false, 0, 1},
};

// Settings sliders (labels verbatim from evidence)
static float s_hpValue = 100.f, s_armorValue = 100.f, s_abSpeed = 1.f, s_abIncr = 0.5f;
static float s_maxDist = 300.f, s_crossSize = 12.f;
static bool  s_groundWarp = true, s_enterVehicle = true;
static bool  s_hideObsDiscord = false, s_antiAfk = false;

// Config tab
struct ConfigItem { std::string name; };
static std::vector<ConfigItem> s_configs;
static bool s_configsScanned = false;
static char s_cfgName[64] = "default";
static int  s_cfgSel = -1;
static bool s_watermark = true, s_notifications = true;
static int  s_toggleKey = VK_INSERT;   // "Menu Toggle Key" (evidence: "Insert")
static bool s_waitingForKey = false;

// Keybinds ("Keybind's" / "##keybinds")
struct Bind { std::string action; int key; int mode; }; // mode: 0 Hold, 1 Toggle
static std::vector<Bind> s_binds;
static int  s_bindCapture = -1; // index awaiting key ("Press a key...")

// Vehicles
static int s_vehicleSel = 0;

// ---------------------------------------------------------------------------
// Colors — purple theme from the runtime screenshot
// ---------------------------------------------------------------------------
static const ImVec4 kAccent      = ImVec4(0.48f, 0.22f, 0.85f, 1.00f);
static const ImVec4 kAccentHover = ImVec4(0.56f, 0.30f, 0.92f, 1.00f);
static const ImVec4 kTabIdle     = ImVec4(0.16f, 0.10f, 0.24f, 1.00f);
static const ImVec4 kPanelBg     = ImVec4(0.09f, 0.06f, 0.14f, 1.00f);
static const ImVec4 kWindowBg    = ImVec4(0.07f, 0.04f, 0.11f, 1.00f);

void NrthUI_ApplyTheme()
{
    ImGuiStyle &st = ImGui::GetStyle();
    st.WindowRounding = 8.f;
    st.ChildRounding  = 6.f;
    st.FrameRounding  = 4.f;
    st.GrabRounding   = 4.f;
    st.WindowBorderSize = 1.f;
    st.FrameBorderSize  = 0.f;
    st.WindowPadding = ImVec2(12, 12);
    st.ItemSpacing   = ImVec2(8, 6);

    ImVec4 *c = st.Colors;
    c[ImGuiCol_WindowBg]        = kWindowBg;
    c[ImGuiCol_ChildBg]         = kPanelBg;
    c[ImGuiCol_PopupBg]         = ImVec4(0.11f, 0.07f, 0.17f, 1.f);
    c[ImGuiCol_Border]          = ImVec4(0.35f, 0.22f, 0.55f, 0.6f);
    c[ImGuiCol_FrameBg]         = ImVec4(0.14f, 0.09f, 0.22f, 1.f);
    c[ImGuiCol_FrameBgHovered]  = kAccentHover;
    c[ImGuiCol_FrameBgActive]   = kAccent;
    c[ImGuiCol_Button]          = kTabIdle;
    c[ImGuiCol_ButtonHovered]   = kAccentHover;
    c[ImGuiCol_ButtonActive]    = kAccent;
    c[ImGuiCol_Header]          = kTabIdle;
    c[ImGuiCol_HeaderHovered]   = kAccentHover;
    c[ImGuiCol_HeaderActive]    = kAccent;
    c[ImGuiCol_Tab]             = kTabIdle;
    c[ImGuiCol_TabHovered]      = kAccentHover;
    c[ImGuiCol_TabActive]       = kAccent;
    c[ImGuiCol_TitleBg]         = kWindowBg;
    c[ImGuiCol_TitleBgActive]   = kWindowBg;
    c[ImGuiCol_Separator]       = ImVec4(0.35f, 0.22f, 0.55f, 0.6f);
    c[ImGuiCol_CheckMark]       = kAccent;
    c[ImGuiCol_SliderGrab]      = kAccent;
    c[ImGuiCol_SliderGrabActive]= kAccentHover;
    c[ImGuiCol_Text]            = ImVec4(0.93f, 0.91f, 0.98f, 1.f);
}

// ---------------------------------------------------------------------------
// FeatureAction: original status messages are reproduced (UI fidelity); the
// game-state / netcode / VM-injection internals are NOT re-implemented (they
// are active exploit behavior — see classification note at top of file).
// ---------------------------------------------------------------------------
static void FeatureAction(const char *msg)
{
    s_lastAction = msg;
}

static void ScanLuaScripts()
{
    s_scripts.clear();
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("lua\\*.*", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                s_scripts.push_back({fd.cFileName, false});
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    s_scriptsScanned = true;
}

static void ScanConfigs()
{
    s_configs.clear();
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("*.ovr", &fd);   // evidence "\*.ovr" / ".ovr" / "OVRCFG"
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                s_configs.push_back({fd.cFileName});
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    s_configsScanned = true;
}

// ---------------------------------------------------------------------------
// Small UI helpers
// ---------------------------------------------------------------------------
static bool TabButton(const char *label, const char *hiddenId, bool active, const ImVec2 &size)
{
    if (active) {
        ImGui::PushStyleColor(ImGuiCol_Button, kAccent);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kAccentHover);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, kAccentHover);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, kTabIdle);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kAccentHover);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, kAccent);
    }
    char buf[128];
    snprintf(buf, sizeof(buf), "%s##%s", label, hiddenId);
    bool clicked = ImGui::Button(buf, size);
    ImGui::PopStyleColor(3);
    return clicked;
}

static void StatusLine()
{
    ImGui::TextColored(kAccentHover, "%s", s_status.c_str());
    if (!s_lastAction.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("| %s", s_lastAction.c_str());
    }
}

// ===========================================================================
// Scripts tab
// ===========================================================================
static void DrawEditor()
{
    // Line-number gutter + code editor ("##lua_editor")
    ImGui::BeginChild("##lua_gutter", ImVec2(48, -70), true);
    int lines = 1;
    for (const char *p = s_editorBuf; *p; ++p) if (*p == '\n') ++lines;
    for (int i = 1; i <= lines && i < 2000; ++i) {
        ImGui::TextDisabled("%d", i);
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::PushItemWidth(-1);
    ImGui::InputTextMultiline("##lua_editor", s_editorBuf, sizeof(s_editorBuf),
                              ImVec2(-1, -70), ImGuiInputTextFlags_AllowTabInput);
    ImGui::PopItemWidth();

    // Execute row
    if (ImGui::Button("Execute", ImVec2(110, 34))) {
        // Original: compiles buffer and injects into MTA Lua VM(s) ("Default VM").
        // VM-injection internals = class U / not re-implemented (see header note).
        FeatureAction("Script executed");   // status string [evidence 0xe98b8]
    }
    ImGui::SameLine();
    const char *vms[] = {"Default VM", "@custom"};   // [0xe9884 / 0xe9890]
    ImGui::SetNextItemWidth(160);
    ImGui::Combo("##vm_combo", &s_vmIndex, vms, 2);
    ImGui::SameLine();
    ImGui::TextDisabled("Target: %s", vms[s_vmIndex]);
}

static void DrawScriptsList()
{
    if (!s_scriptsScanned) ScanLuaScripts();
    ImGui::TextDisabled("Path: .\\lua\\   (evidence: \"%%s\\\\lua\\\\%%s\")");
    ImGui::BeginChild("##scripts_list", ImVec2(-1, -80), true);
    if (s_scripts.empty()) {
        ImGui::TextDisabled("No scripts found");          // [0xe98c8]
    }
    for (int i = 0; i < (int)s_scripts.size(); ++i) {
        ImGui::PushID(i);
        if (ImGui::Selectable(s_scripts[i].name.c_str(), s_scriptSel == i)) s_scriptSel = i;
        ImGui::SameLine(220);
        char lbl[64];
        snprintf(lbl, sizeof(lbl), "Inject##%d", i);      // [0xe98ec]
        if (ImGui::SmallButton(lbl)) FeatureAction(("Injected: " + s_scripts[i].name).c_str());
        ImGui::SameLine();
        snprintf(lbl, sizeof(lbl), "Auto-inj##%d", i);    // [0xe98fc]
        ImGui::Checkbox(lbl, &s_scripts[i].autoInject);
        ImGui::PopID();
    }
    ImGui::EndChild();
    if (ImGui::Button("Dump")) {                          // [0xe9950]
        if (s_scriptSel >= 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Dump script saved: %s", s_scripts[s_scriptSel].name.c_str());
            FeatureAction(msg);                           // [0xe99a0]
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Dump all")) {                      // [0xe99b8]
        char msg[128];
        snprintf(msg, sizeof(msg), "Dump all scripts saved (%d)", (int)s_scripts.size());
        FeatureAction(msg);                               // [0xe9970]
    }
    ImGui::SameLine();
    ImGui::TextDisabled("view: ##script_editor_view | \"File big, no view script\"");
}

static void DrawResources()
{
    ImGui::TextDisabled("Resources (stop/block — server side effects not re-implemented)");
    static char search[64] = "";
    ImGui::InputTextWithHint("##res_search", "Search...", search, sizeof(search));
    static int resSel = 0;
    ImGui::SetNextItemWidth(260);
    ImGui::BeginCombo("##res_combo", s_resources.empty() ? "Select Resource" : s_resources[resSel].c_str());
    for (int i = 0; i < (int)s_resources.size(); ++i)
        if (ImGui::Selectable(s_resources[i].c_str(), resSel == i)) resSel = i;
    ImGui::EndCombo();
    if (ImGui::Button("Stop Resource")) {                 // [0xeab20]
        if (!s_resources.empty()) {
            char msg[128];
            snprintf(msg, sizeof(msg), "Resource stopped: %s", s_resources[resSel].c_str());
            FeatureAction(msg);                           // [0xeaaf0]
        }
    }
    ImGui::Separator();
    ImGui::TextDisabled("Block list (\" (blocked)\"):");
    for (auto &e : s_blockedEvents) ImGui::BulletText("%s (blocked)", e.c_str());
}

static void DrawEvents()
{
    static int evSel = 0;
    static const char *kEvents[] = {"onClientRender", "onClientPlayerDamage", "onClientVehicleEnter",
                                    "onClientChatMessage", "onClientElementDataChange", "onClientPreRender"};
    ImGui::SetNextItemWidth(280);
    ImGui::BeginCombo("##event_combo", kEvents[evSel]);     // "Select Event" default
    for (int i = 0; i < 6; ++i) if (ImGui::Selectable(kEvents[i], evSel == i)) evSel = i;
    ImGui::EndCombo();
    ImGui::SameLine();
    if (ImGui::Button("Block##event")) {                    // [0xeab30]
        s_blockedEvents.push_back(kEvents[evSel]);
        FeatureAction(("Event blocked: " + std::string(kEvents[evSel])).c_str());  // [0xeab40]
    }
    ImGui::SameLine();
    if (ImGui::Button("Unblock##event") && !s_blockedEvents.empty()) {
        FeatureAction(("Event unblocked: " + s_blockedEvents.back()).c_str());     // [0xeaba8]
        s_blockedEvents.pop_back();
    }
    static char trig[96] = "";
    ImGui::InputTextWithHint("##trigger_input", "triggerServerEvent name...", trig, sizeof(trig));
    ImGui::SameLine();
    if (ImGui::Button("Add to Block List") && trig[0]) {    // [0xeab84]
        s_blockedEvents.push_back(trig);
        trig[0] = 0;
    }
    ImGui::Separator();
    ImGui::Text("Recent Triggers:");                        // [0xeabe4]
    if (s_recentTriggers.empty()) ImGui::TextDisabled("No triggers");
    for (auto &t : s_recentTriggers) ImGui::BulletText("%s", t.c_str());
}

static void DrawEventsTable()
{
    ImGui::TextDisabled("Events Table (live event registry view)");
    if (ImGui::BeginTable("##events_table", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Event");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("State");
        ImGui::TableHeadersRow();
        for (auto &e : s_recentTriggers) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(e.c_str());
            ImGui::TableNextColumn(); ImGui::TextDisabled("client");
            ImGui::TableNextColumn(); ImGui::TextDisabled("tracked");
        }
        for (auto &e : s_blockedEvents) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(e.c_str());
            ImGui::TableNextColumn(); ImGui::TextDisabled("client");
            ImGui::TableNextColumn(); ImGui::TextColored(kAccentHover, "(blocked)");
        }
        ImGui::EndTable();
    }
}

static void DrawPackets()
{
    // Toolbar: "Refresh" "Packets: %zu" "Clear All" "Unblock All" + search
    if (ImGui::Button("Refresh")) FeatureAction("Refresh");       // [0xeac5c]
    ImGui::SameLine();
    ImGui::Text("Packets: %zu", s_packets.size());                // [0xeac64]
    ImGui::SameLine();
    if (ImGui::Button("Clear All")) s_packets.clear();            // [0xeac74]
    ImGui::SameLine();
    if (ImGui::Button("Unblock All"))                             // [0xeac80]
        for (auto &p : s_packets) p.blocked = false;
    ImGui::SameLine();
    ImGui::InputTextWithHint("##packet_search", "Search packet...", s_packetSearch, sizeof(s_packetSearch));

    ImGui::BeginChild("packets_left", ImVec2(-320, -1), true);    // IDs [0xeac94/0xeacd4]
    if (s_packets.empty()) {
        ImGui::TextDisabled("No packets detected.");              // [0xeaca4]
    }
    for (int i = 0; i < (int)s_packets.size(); ++i) {
        ImGui::PushID(i);
        if (ImGui::Selectable(s_packets[i].name.c_str(), s_packetSel == i)) s_packetSel = i;
        ImGui::SameLine();
        ImGui::TextDisabled("%s", s_packets[i].blocked ? "BLOCKED" : "UNBLOCKED");
        ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("packets_right", ImVec2(0, -1), true);
    if (s_packetSel >= 0 && s_packetSel < (int)s_packets.size()) {
        const PacketRow &p = s_packets[s_packetSel];
        ImGui::Text("Name: %s", p.name.c_str());                  // [0xeacbc]
        ImGui::Text("Time: %s", p.time.c_str());                  // [0xeacc8]
        ImGui::Text("ID: %d", p.id);                              // [0eace4]
        ImGui::TextColored(kAccentHover, "%s", p.blocked ? "BLOCKED" : "UNBLOCKED");
        if (ImGui::Button("Block Packet"))                        // [0xead08]
            s_packets[s_packetSel].blocked = !s_packets[s_packetSel].blocked;
        ImGui::SameLine();
        if (ImGui::Button("Resend")) {                            // [0xead20]
            char msg[160];
            snprintf(msg, sizeof(msg), "Resending packet: %s", p.name.c_str());
            FeatureAction(msg);                                   // [0xead28]
        }
        ImGui::SameLine();
        if (ImGui::Button("Copy Name")) {                         // [0xead40]
            ImGui::SetClipboardText(p.name.c_str());
            char msg[160];
            snprintf(msg, sizeof(msg), "Packet name copied: %s", p.name.c_str());
            FeatureAction(msg);                                   // [0xead4c]
        }
    } else {
        ImGui::TextDisabled("Select a packet");                   // [0xead64]
    }
    ImGui::EndChild();
}

// ===========================================================================
// Dumper tab — "Address: 0x" memory/class dump display (evidence 0x916d)
// ===========================================================================
static void DrawDumper()
{
    ImGui::TextDisabled("Memory / class dumper (display shell)");
    ImGui::BeginChild("##dumper", ImVec2(-1, -1), true);
    for (int i = 0; i < 8; ++i) {
        ImGui::Text("Address: 0x%08X", 0x10000000 + i * 0x10);   // evidence "Address: 0x"
        ImGui::SameLine(180);
        ImGui::TextDisabled("?? ?? ?? ??  (dump data — U)");
    }
    ImGui::EndChild();
}

// ===========================================================================
// Cheat tab
// ===========================================================================
static void DrawPlayerTab()
{
    ImGui::InputTextWithHint("##player_filter", "filter...", (char *)s_playerFilter.c_str(), 64);
    ImGui::SetNextItemWidth(280);
    std::string preview = s_players.empty() ? "Select player..." :
        (s_players[s_playerSel].name + (s_players[s_playerSel].isYou ? " (you)" : ""));
    if (ImGui::BeginCombo("##player_combo", preview.c_str())) {   // " (you)" [0xe99d4]
        for (int i = 0; i < (int)s_players.size(); ++i) {
            std::string lbl = s_players[i].name + (s_players[i].isYou ? " (you)" : "");
            if (ImGui::Selectable(lbl.c_str(), s_playerSel == i)) s_playerSel = i;
        }
        if (s_players.empty()) ImGui::TextDisabled("No players found");   // [0xe99dc]
        ImGui::EndCombo();
    }
    if (ImGui::Button("Teleport")) FeatureAction("Teleport");    // [0xe9a30]
    ImGui::SameLine();
    if (ImGui::Button("Bomb")) FeatureAction("Bomb");            // [0xe9a3c]
    ImGui::SameLine();
    if (ImGui::Button("Add Friend")) {                           // [0xe9a24]
        if (!s_players.empty()) s_friends.push_back(s_players[s_playerSel].name);
    }
    ImGui::SameLine();
    if (ImGui::Button("Delete Friend") && !s_friends.empty())    // [0xe9a14]
        s_friends.pop_back();
    ImGui::Separator();
    ImGui::Text("Friend's list");                                // [0xe9a58]
    if (s_friends.empty()) ImGui::TextDisabled("No friends added");
    for (auto &f : s_friends) ImGui::BulletText("%s", f.c_str());
}

static void FeatureRow(Feature &f, const char *id)
{
    ImGui::PushID(id);
    ImGui::Checkbox(f.label, &f.on);
    ImGui::SameLine();
    if (ImGui::SmallButton("##gear")) ImGui::OpenPopup("##settings_panel");  // [0xe9554]
    if (ImGui::BeginPopup("##settings_panel")) {
        ImGui::TextUnformatted(f.settings);                      // e.g. "GodMode Settings"
        ImGui::Separator();
        if (strcmp(f.label, "Give HP") == 0) {
            ImGui::SliderFloat("HP Value##sp", &s_hpValue, 1, 200);         // [0xe95f8]
        } else if (strcmp(f.label, "Give Armor") == 0) {
            ImGui::SliderFloat("Armor Value##sp", &s_armorValue, 1, 200);   // [0xe95e8]
        } else if (strcmp(f.label, "AirBreak") == 0) {
            ImGui::SliderFloat("Speed: %.2f", &s_abSpeed, 0.1f, 10.f);     // label fmt [0xe9578]
            ImGui::SliderFloat("Increment: %.2f", &s_abIncr, 0.05f, 2.f);  // [0xe9594]
            ImGui::Separator();
            ImGui::Text("Keybinds");                                             // [0xe95a8]
            ImGui::BulletText("Forward:"); ImGui::BulletText("Back:");
            ImGui::BulletText("Left:");    ImGui::BulletText("Right:");
            ImGui::BulletText("Down:");
        } else if (strcmp(f.label, "Click Warp") == 0) {
            ImGui::SliderFloat("Max Distance##sp", &s_maxDist, 10, 1000);   // [0xe961c]
            ImGui::SliderFloat("Crosshair Size##sp", &s_crossSize, 2, 40);  // [0xe9608]
            ImGui::Checkbox("Ground Warp##sp", &s_groundWarp);              // [0xe9630]
            ImGui::Checkbox("Enter Vehicle##sp", &s_enterVehicle);          // [0xe9640]
        } else if (strcmp(f.label, "Anti-ScreenShot") == 0) {
            ImGui::Checkbox("Hide obs/discord", &s_hideObsDiscord);         // [0xe9b14]
        } else if (strcmp(f.label, "Anti-AFK") == 0) {
            ImGui::Checkbox("Anti-AFK", &s_antiAfk);                        // [0xe9b3c]
        } else {
            ImGui::TextDisabled("settings shell (U)");
        }
        ImGui::Separator();
        // keybind capture: "Press a key..." [0xe9534 / 0xeb124]
        if (ImGui::Button("Press a key...")) s_bindCapture = -2;
        ImGui::SameLine();
        ImGui::TextDisabled("mode: Toggle/Hold");                           // [0xe90b8/0xe9098]
        ImGui::EndPopup();
    }
    ImGui::PopID();
}

static void DrawOtherTab()
{
    ImGui::TextDisabled("Feature toggles (statuses real; game-state internals U/stub)");
    for (int i = 0; i < (int)(sizeof(s_cheatFeatures) / sizeof(Feature)); ++i) {
        char id[32];
        snprintf(id, sizeof(id), "cf%d", i);
        FeatureRow(s_cheatFeatures[i], id);
    }
    if (!s_lastAction.empty()) ImGui::TextDisabled("last: %s", s_lastAction.c_str());
}

static void DrawMarkersTab()
{
    ImGui::InputTextWithHint("##marker_name", "marker name...", s_markerName, sizeof(s_markerName));
    ImGui::SameLine();
    if (ImGui::Button("Save") && s_markerName[0]) {              // [0xe9a98]
        MarkerRow m = {s_markerName, 0.f, 0.f, 0.f};
        s_markers.push_back(m);
        s_markerName[0] = 0;
    }
    if (s_markers.empty()) ImGui::TextDisabled("No markers saved");   // [0xe9aa0]
    for (auto &m : s_markers) {
        char line[128];
        snprintf(line, sizeof(line), "%s (%.1f, %.1f, %.1f)", m.name.c_str(), m.x, m.y, m.z);
        ImGui::BulletText("%s", line);                            // fmt [0xe9a7c]
        ImGui::SameLine(280);
        if (ImGui::SmallButton("Teleport")) FeatureAction("Teleport");
        ImGui::SameLine();
        if (ImGui::SmallButton("Delete")) m.name.clear();
    }
}

// ===========================================================================
// Vehicle tab
// ===========================================================================
static void DrawVehicleTab()
{
    ImGui::Columns(2, "##vehcols", false);
    ImGui::SetColumnWidth(0, 300);
    ImGui::Text("Vehicle's");                                    // [0xe91c4]
    ImGui::Separator();
    for (int i = 0; i < (int)(sizeof(s_vehicleFeatures) / sizeof(Feature)); ++i) {
        char id[32];
        snprintf(id, sizeof(id), "vf%d", i);
        FeatureRow(s_vehicleFeatures[i], id);
    }
    ImGui::NextColumn();

    ImGui::Text("Vehicles List");                                // [0xeaf0c]
    ImGui::SetNextItemWidth(-1);
    std::string prev = std::string(kVehicleNames[s_vehicleSel]) + " (HP: 1000)"; // fmt [0xeaf64]
    if (ImGui::BeginCombo("##vehicles_combo", s_vehicleSel >= 0 ? prev.c_str() : "Select vehicle...")) {
        for (int i = 0; i < (int)(sizeof(kVehicleNames) / sizeof(kVehicleNames[0])); ++i) {
            if (ImGui::Selectable(kVehicleNames[i], s_vehicleSel == i)) s_vehicleSel = i;
        }
        ImGui::EndCombo();
    }
    if (ImGui::Button("Teleport to Vehicle")) FeatureAction("Teleport to Vehicle");  // [0xeaf50]
    ImGui::SameLine();
    if (ImGui::Button("Teleport Vehicle")) FeatureAction("Vehicle teleported to you"); // [0xeaf88]
    ImGui::SameLine();
    if (ImGui::Button("Bomb Car")) FeatureAction("Vehicle destroyed");               // [0xeaf9c]
    if (ImGui::Button("Repair Car")) FeatureAction("Vehicle repaired");              // [0xeadf0]
    ImGui::SameLine();
    if (ImGui::Button("Start Engine")) FeatureAction("Engine started");              // [0xeae04]
    ImGui::SameLine();
    if (ImGui::Button("Stop")) FeatureAction("Vehicle stopped");                     // [0xeadc0]
    ImGui::SameLine();
    if (ImGui::Button("Unlock Car")) FeatureAction("Unlocked nearest vehicle");      // [0xeada4]
    ImGui::Columns(1);
}

// ===========================================================================
// Config tab
// ===========================================================================
static void DrawColorSettings()
{
    if (ImGui::TreeNode("Color Settings")) {                    // [0xe91ec]
        static char filter[64] = "";
        ImGui::InputTextWithHint("##filter", "Search color...", filter, sizeof(filter)); // [0xe91dc]
        static const struct { const char *name; ImGuiCol col; } kColors[] = {
            {"Text", ImGuiCol_Text}, {"Text Disabled", ImGuiCol_TextDisabled},
            {"Window BG", ImGuiCol_WindowBg}, {"Child BG", ImGuiCol_ChildBg},
            {"Popup BG", ImGuiCol_PopupBg}, {"Border", ImGuiCol_Border},
            {"Border Shadow", ImGuiCol_BorderShadow},
            {"Frame BG", ImGuiCol_FrameBg}, {"Frame BG Hovered", ImGuiCol_FrameBgHovered},
            {"Frame BG Active", ImGuiCol_FrameBgActive},
            {"Title BG", ImGuiCol_TitleBg}, {"Title BG Active", ImGuiCol_TitleBgActive},
            {"Title BG Collapsed", ImGuiCol_TitleBgCollapsed},
            {"Menu Bar BG", ImGuiCol_MenuBarBg},
            {"Scrollbar BG", ImGuiCol_ScrollbarBg},
            {"Scrollbar Grab", ImGuiCol_ScrollbarGrab},
            {"Scrollbar Grab Hovered", ImGuiCol_ScrollbarGrabHovered},
            {"Scrollbar Grab Active", ImGuiCol_ScrollbarGrabActive},
            {"Check Mark", ImGuiCol_CheckMark}, {"Slider Grab", ImGuiCol_SliderGrab},
            {"Slider Grab Active", ImGuiCol_SliderGrabActive},
            {"Button", ImGuiCol_Button}, {"Button Hovered", ImGuiCol_ButtonHovered},
            {"Button Active", ImGuiCol_ButtonActive},
            {"Header", ImGuiCol_Header}, {"Header Hovered", ImGuiCol_HeaderHovered},
            {"Header Active", ImGuiCol_HeaderActive},
            {"Separator Hovered", ImGuiCol_SeparatorHovered},
            {"Separator Active", ImGuiCol_SeparatorActive},
            {"Tab", ImGuiCol_Tab}, {"Tab Hovered", ImGuiCol_TabHovered},
            {"Tab Active", ImGuiCol_TabActive},
            {"Resize Grip", ImGuiCol_ResizeGrip},
            {"Resize Grip Hovered", ImGuiCol_ResizeGripHovered},
            {"Resize Grip Active", ImGuiCol_ResizeGripActive},
            {"Text Selected BG", ImGuiCol_TextSelectedBg},
        };
        if (ImGui::BeginTable("##ColorTable", 2, ImGuiTableFlags_Borders)) {   // [0xe943c]
            ImGui::TableSetupColumn("Name");                                    // [0xe9460]
            ImGui::TableSetupColumn("Color");                                   // [0xe9458]
            ImGui::TableHeadersRow();
            for (auto &k : kColors) {
                if (filter[0] && !strstr(k.name, filter)) continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextUnformatted(k.name);
                ImGui::TableNextColumn();
                ImVec4 c = ImGui::GetStyle().Colors[k.col];
                if (ImGui::ColorEdit4("##col", (float *)&c, ImGuiColorEditFlags_NoInputs))
                    ImGui::GetStyle().Colors[k.col] = c;
            }
            ImGui::EndTable();
        }
        if (ImGui::Button("Reset Colors")) {                                    // [0xe9468]
            ImGui::StyleColorsDark();
            NrthUI_ApplyTheme();
            FeatureAction("Colors reset");                                      // [0xe9488]
        }
        ImGui::TreePop();
    }
}

static void DrawConfigTab()
{
    if (!s_configsScanned) ScanConfigs();
    ImGui::Columns(2, "##cfgcols", false);
    ImGui::SetColumnWidth(0, 260);
    ImGui::Text("Configs");                                       // [0xe9b0b0]
    ImGui::BeginChild("##cfgitem", ImVec2(-1, -1), true);
    if (s_configs.empty()) ImGui::TextDisabled("No configs found"); // [0xe9b090]
    for (int i = 0; i < (int)s_configs.size(); ++i) {
        if (ImGui::Selectable(s_configs[i].name.c_str(), s_cfgSel == i)) s_cfgSel = i;
    }
    ImGui::EndChild();
    ImGui::NextColumn();

    ImGui::BeginChild("##cfg_right", ImVec2(0, -1), true);
    ImGui::InputText("Name##sa", s_cfgName, sizeof(s_cfgName));    // [0xe9b0b8]
    if (ImGui::Button("Save")) {                                   // [0xe9a98]
        std::string f = std::string(s_cfgName) + ".ovr";           // ".ovr" [0xe9b034]
        FILE *fp = fopen(f.c_str(), "w");
        if (fp) {
            fputs("OVRCFG\n", fp);                                 // "OVRCFG" [0xe9b018]
            fclose(fp);
        }
        char msg[128];
        snprintf(msg, sizeof(msg), "Config saved: %s", f.c_str()); // [0xe9b020]
        FeatureAction(msg);
        s_configsScanned = false;
    }
    ImGui::SameLine();
    if (ImGui::Button("Save As...")) {                             // [0xe9b0d8]
        s_cfgName[0] = 0;
    }
    ImGui::SameLine();
    if (ImGui::Button("Load") && s_cfgSel >= 0) {                  // [0xe9b104]
        char msg[128];
        snprintf(msg, sizeof(msg), "Config loaded: %s", s_configs[s_cfgSel].name.c_str());
        FeatureAction(msg);                                        // [0xe9b05c]
    }
    ImGui::SameLine();
    if (ImGui::Button("Delete") && s_cfgSel >= 0) {                // [0xe9b10c]
        DeleteFileA(s_configs[s_cfgSel].name.c_str());
        char msg[128];
        snprintf(msg, sizeof(msg), "Config deleted: %s", s_configs[s_cfgSel].name.c_str());
        FeatureAction(msg);                                        // [0xe9b070]
        s_configsScanned = false;
    }
    ImGui::SameLine();
    if (ImGui::Button("Reset to Default")) {                       // [0xe9b0e4]
        FeatureAction("Reset to default style");                   // [0xe9b03c]
    }
    ImGui::Separator();
    ImGui::Checkbox("Watermark", &s_watermark);                    // [0xe9b0f8]
    ImGui::SameLine();
    ImGui::Checkbox("Notifications", &s_notifications);            // [0xe9b13c]
    ImGui::Separator();

    // Menu Toggle Key (evidence [0xe9b114]) + key capture
    ImGui::Text("Menu Toggle Key");
    ImGui::SameLine();
    if (s_waitingForKey) {
        ImGui::Button("Press...");                                 // [0xe9b124]
        for (int k = 0; k < 256; ++k)
            if (ImGui::IsKeyPressed((ImGuiKey)k, false)) { s_toggleKey = k; s_waitingForKey = false; }
    } else if (ImGui::Button("Set")) {
        s_waitingForKey = true;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(current: Insert)");

    ImGui::Separator();
    ImGui::Text("Keybind's");                                      // [0xe9b130 / 0xe9110]
    if (s_binds.empty()) ImGui::TextDisabled("No binds");
    for (int i = 0; i < (int)s_binds.size(); ++i) {
        ImGui::Text("Bind: %s -> key %d", s_binds[i].action.c_str(), s_binds[i].key); // fmt [0xe9194]
        ImGui::SameLine();
        if (ImGui::SmallButton("X")) {
            FeatureAction(("Bind cleared: " + s_binds[i].action).c_str());           // [0xe91a4]
            s_binds.erase(s_binds.begin() + i);
            break;
        }
    }
    DrawColorSettings();
    ImGui::EndChild();
    ImGui::Columns(1);
}

// ===========================================================================
// Entry point (called from Hooked_Present while menu open)
// ===========================================================================
void NrthUI_Build()
{
    // Status overlay top-left — "No connected server." (runtime screenshot)
    ImGui::SetNextWindowPos(ImVec2(10, 10), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(0.35f);
    ImGui::Begin("##status_ovr", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
                 ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                 ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoMove);
    ImGui::TextUnformatted(s_status.c_str());
    ImGui::End();

    ImGui::SetNextWindowSize(ImVec2(860, 560), ImGuiCond_FirstUseEver);
    if (!s_menuOpen) return;
    if (!ImGui::Begin("North Cheat", &s_menuOpen)) {               // title [0xe9d8]
        ImGui::End();
        return;
    }

    StatusLine();
    ImGui::Separator();

    // Top tab row (flat buttons matching the screenshot)
    static const char *kTop[] = {"Scripts", "Dumper", "Cheat", "Vehicle", "Config"};
    float w = (ImGui::GetContentRegionAvail().x - 4 * 8.f) / 5.f;
    for (int i = 0; i < 5; ++i) {
        char hid[32];
        snprintf(hid, sizeof(hid), "nvx_top_%d", i);              // "%s##nvx_top_%d" [0xe94b0]
        if (TabButton(kTop[i], hid, s_topTab == i, ImVec2(w, 34))) s_topTab = i;
        if (i < 4) ImGui::SameLine();
    }
    ImGui::Spacing();

    if (s_topTab == 0) {
        // Scripts sub-tab bar
        static const char *kSub[] = {"Editor", "Scripts", "Resources", "Events", "Events Table", "Packets"};
        float sw = (ImGui::GetContentRegionAvail().x - 5 * 6.f) / 6.f;
        for (int i = 0; i < 6; ++i) {
            char hid[32];
            snprintf(hid, sizeof(hid), "nvx_ssub_%d", i);         // "%s##nvx_ssub_%d" [0xe94f4]
            if (TabButton(kSub[i], hid, s_scriptsSub == i, ImVec2(sw, 26))) s_scriptsSub = i;
            if (i < 5) ImGui::SameLine();
        }
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);   // [0xe9514]
        switch (s_scriptsSub) {
            case 0: DrawEditor();       break;
            case 1: DrawScriptsList();  break;
            case 2: DrawResources();    break;
            case 3: DrawEvents();       break;
            case 4: DrawEventsTable();  break;
            case 5: DrawPackets();      break;
        }
        ImGui::EndChild();
    } else if (s_topTab == 1) {
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        DrawDumper();
        ImGui::EndChild();
    } else if (s_topTab == 2) {
        static const char *kCSub[] = {"Player", "Other", "Markers"};   // [0xe94ec/0xe9504/0xe950c]
        float sw = (ImGui::GetContentRegionAvail().x - 2 * 6.f) / 3.f;
        for (int i = 0; i < 3; ++i) {
            char hid[32];
            snprintf(hid, sizeof(hid), "nvx_csub_%d", i);         // "%s##nvx_csub_%d" [0xe9524]
            if (TabButton(kCSub[i], hid, s_cheatSub == i, ImVec2(sw, 26))) s_cheatSub = i;
            if (i < 2) ImGui::SameLine();
        }
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        switch (s_cheatSub) {
            case 0: DrawPlayerTab();  break;
            case 1: DrawOtherTab();   break;
            case 2: DrawMarkersTab(); break;
        }
        ImGui::EndChild();
    } else if (s_topTab == 3) {
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        DrawVehicleTab();
        ImGui::EndChild();
    } else {
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        DrawConfigTab();
        ImGui::EndChild();
    }

    ImGui::End();
}
