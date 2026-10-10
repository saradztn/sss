NORTH Loader & NRTH.dll - rebuilt x86 (PE32) - R2 reconstruction
===============================================================
SHA-256:
  NORTH_LOADER.exe  75a3dc1798b0231b9a0178027f8d17b44c6bef4a5dfc854077ac7748fdd2b3dd
  NRTH.dll          452c58488dabb85705e5e189d9873c208174a798ae18fe6cdc6e121c8d6e383f

Use (authorized private-server testing only):
  1. Put NORTH_LOADER.exe and NRTH.dll in the same folder.
  2. Run NORTH_LOADER.exe, then start the game.
  3. In-game press INSERT for the menu.
  Options: --proc <name>  --dll <path>  --autoclose

Notes:
  - Menu feature slots are stubs (original feature logic unmapped - class U).
  - Built 2026-10-10 with build.sh (Zig 0.17.0 MinGW, target x86-windows-gnu).
  - Full source + rebuild script: recovered_or_reconstructed_project/ in this repo.
