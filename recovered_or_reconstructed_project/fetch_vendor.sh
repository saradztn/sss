#!/usr/bin/env bash
# Fetch pinned third-party libraries used by the reconstruction.
# These are well-known open-source libraries the ORIGINAL sample also embedded
# (MinHook v1.3.3, Dear ImGui 1.92.9 WIP) — vendored here for build reproducibility.
set -euo pipefail
cd "$(dirname "$0")/vendor" 2>/dev/null || { mkdir -p "$(dirname "$0")/vendor"; cd "$(dirname "$0")/vendor"; }

if [ ! -d minhook ]; then
  git clone --depth 1 https://github.com/TsudaKageyu/minhook.git
fi
if [ ! -d lua ]; then
  git clone --depth 1 --branch v5.4.6 https://github.com/lua/lua.git
fi
if [ ! -d imgui ]; then
  git clone --depth 1 --branch v1.92.9 https://github.com/ocornut/imgui.git
fi

echo "[+] Vendor trees ready:"
echo "    minhook: $(git -C minhook rev-parse HEAD)"
echo "    imgui:   $(git -C imgui rev-parse HEAD) ($(git -C imgui describe --tags))"
