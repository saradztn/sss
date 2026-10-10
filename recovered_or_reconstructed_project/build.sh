#!/usr/bin/env bash
# ============================================================================
# Cross-build script: produces Windows x86 (PE32) artifacts matching the sample
# architecture:
#   build/NORTH_LOADER.exe   (console EXE — loader/injector reconstruction)
#   build/NRTH.dll           (DLL — payload/overlay reconstruction)
#
# Toolchain: Zig's bundled MinGW sysroot (ziglang on PyPI), target x86-windows-gnu.
# Vendored libraries (fetched by `fetch_vendor.sh`, pinned):
#   vendor/minhook  — MinHook (the sample embeds MinHook v1.3.3)
#   vendor/imgui    — Dear ImGui v1.92.9 (sample embeds 1.92.9 WIP (19283))
#
# Scope: authorized MTA:SA blue-team private-server validation ONLY.
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

ZIG="python3 -m ziglang"
TARGET="-target x86-windows-gnu"
OUT=bin
OBJ="$OUT/obj"
mkdir -p "$OBJ"

echo "[*] Compiling MinHook (x86)..."
for f in buffer hook trampoline; do
  $ZIG cc $TARGET -O2 -Ivendor/minhook/include -c "vendor/minhook/src/$f.c" -o "$OBJ/mh_$f.o"
done
$ZIG cc $TARGET -O2 -Ivendor/minhook/include -c vendor/minhook/src/hde/hde32.c -o "$OBJ/mh_hde32.o"
$ZIG cc $TARGET -O2 -Ivendor/minhook/include -c vendor/minhook/src/hde/hde64.c -o "$OBJ/mh_hde64.o"

echo "[*] Compiling Dear ImGui v1.92.9 (core + DX9/Win32 backends)..."
for f in imgui imgui_draw imgui_tables imgui_widgets; do
  $ZIG c++ $TARGET -O2 -Ivendor/imgui -c "vendor/imgui/$f.cpp" -o "$OBJ/$f.o"
done
$ZIG c++ $TARGET -O2 -Ivendor/imgui -Ivendor/imgui/backends -c vendor/imgui/backends/imgui_impl_dx9.cpp -o "$OBJ/imgui_impl_dx9.o"
$ZIG c++ $TARGET -O2 -Ivendor/imgui -Ivendor/imgui/backends -c vendor/imgui/backends/imgui_impl_win32.cpp -o "$OBJ/imgui_impl_win32.o"

echo "[*] Compiling Lua 5.4.6 (embedded sandbox script VM)..."
for f in vendor/lua/*.c; do
  base=$(basename "$f" .c)
  case "$base" in lua|luac|onelua) continue ;; esac
  $ZIG cc $TARGET -O2 -Ivendor/lua -c "$f" -o "$OBJ/lua_$base.o"
done

echo "[*] Compiling NRTH.dll reconstruction (src/nrth_hook.cpp + src/nrth_ui.cpp)..."
$ZIG c++ $TARGET -O2 -Isrc -Ivendor/minhook/include -Ivendor/imgui -Ivendor/imgui/backends \
  -c src/nrth_hook.cpp -o "$OBJ/nrth_hook.o"
$ZIG c++ $TARGET -O2 -Isrc -Ivendor/minhook/include -Ivendor/imgui -Ivendor/imgui/backends \
  -Ivendor/lua -c src/nrth_ui.cpp -o "$OBJ/nrth_ui.o"

echo "[*] Linking build/NRTH.dll (export: NVXHookProc @1)..."
$ZIG c++ $TARGET -shared -o "$OUT/NRTH.dll" \
  "$OBJ/nrth_hook.o" "$OBJ/nrth_ui.o" "$OBJ"/lua_*.o \
  "$OBJ/mh_buffer.o" "$OBJ/mh_hook.o" "$OBJ/mh_trampoline.o" "$OBJ/mh_hde32.o" "$OBJ/mh_hde64.o" \
  "$OBJ/imgui.o" "$OBJ/imgui_draw.o" "$OBJ/imgui_tables.o" "$OBJ/imgui_widgets.o" \
  "$OBJ/imgui_impl_dx9.o" "$OBJ/imgui_impl_win32.o" \
  src/nrth_dll.def \
  -luser32 -lgdi32 -ladvapi32 -ldwmapi -limm32

echo "[*] Compiling NORTH_LOADER.exe reconstruction (src/north_loader.cpp)..."
$ZIG c++ $TARGET -O2 -o "$OUT/NORTH_LOADER.exe" src/north_loader.cpp \
  -luser32 -ladvapi32 -lpsapi

# Same normalisation as build_audit.sh: the reconstruction is evidence, so its hashes should be
# quotable; only timestamp/CodeView/build-id entropy is removed (no code bytes are touched).
python3 tools/pe_deterministic.py "$OUT/NRTH.dll" "$OUT/NORTH_LOADER.exe" || \
  echo "[!] pe_deterministic.py failed - hashes will move on every rebuild" >&2

echo "[+] Build complete:"
ls -l "$OUT/NORTH_LOADER.exe" "$OUT/NRTH.dll"
sha256sum "$OUT/NORTH_LOADER.exe" "$OUT/NRTH.dll"
