NORTH Loader & NRTH.dll - rebuilt x86 (PE32) - R2 reconstruction
===============================================================
Build 2026-10-10 (rev3: full UI + working systems)

WORKING: Lua editor + Execute (embedded Lua 5.4.6 sandbox VM with console
output), Run saved scripts (lua\*.lua), Resources listing from disk
(mods\deathmatch\resources|cache), mouse cursor + input (DirectInput bridge),
config save/load (*.ovr), color editor, keybinds.
SHA-256:
  NORTH_LOADER.exe  27da3e2f5196a988eb20e20edd0c133698ef142bfd3c673e18e9a2b832ecd11c
  NRTH.dll          2a9e38429a679b214c4fc56325638ba99d59e51cd83a65e7bc9d59f08d04f31f

Menu (INSERT key) now matches the real tool's structure:
  Top tabs:     Scripts | Dumper | Cheat | Vehicle | Config
  Scripts:      Editor (lua editor + Execute + VM combo) | Scripts | Resources |
                Events | Events Table | Packets
  Cheat:        Player | Other (GodMode, Give HP/Armor, Infinite Ammo, ...) | Markers
  Vehicle:      Vehicles List (209 GTA:SA names) + vehicle toggles
  Config:       Configs (*.ovr), Color editor, Menu Toggle Key, Keybind's

Use (authorized private-server testing only):
  1. Put NORTH_LOADER.exe and NRTH.dll in the same folder.
  2. Run NORTH_LOADER.exe, then start the game.
  3. In-game press INSERT for the menu.
  Options: --proc <name>  --dll <path>  --autoclose

Notes:
  - UI + local features are reconstructed from evidence (screenshot + strings).
  - Game-state/netcode/Lua-VM-injection internals are NOT re-implemented (stubs).
  - Built with build.sh (Zig 0.17.0 MinGW, x86-windows-gnu).
  - Full source + rebuild script: recovered_or_reconstructed_project/ in this repo.
