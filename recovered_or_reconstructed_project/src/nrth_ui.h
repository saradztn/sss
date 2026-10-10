#pragma once
/**
 * NRTH overlay UI — faithful interface reconstruction (R2) of the REAL menu.
 * Evidence: runtime screenshot (user-supplied) + NRTH.dll .rdata strings
 * (offsets 0x0e8554-0x0eb14c, see analysis/strings_catalog.txt).
 *
 * Real/local features (functional): tab structure, theme, script file listing
 * (.\lua\*.lua), config save/load (*.ovr), style color editor, keybind capture,
 * marker list, vehicle name table, status messages.
 * Game-state / netcode / Lua-VM-injection internals are class U or exploit
 * primitives and are wired to labeled stubs only (see FeatureAction).
 */
void NrthUI_ApplyTheme();   // purple theme matching the runtime screenshot
void NrthUI_Build();        // called once per frame while menu is open
