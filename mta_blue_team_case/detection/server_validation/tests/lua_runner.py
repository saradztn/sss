#!/usr/bin/env python3
"""Execute a Lua script under lupa (Lua 5.x) with `...` set to the resource root.

Usage: python3 lua_runner.py <script.lua> <root-dir>
Exit status: 0 when the Lua script completes without error.

Why this exists: the analysis host has no system Lua interpreter. lupa (PyPI)
embeds a real Lua VM, so the guard's unit/integration tests run as genuine Lua
rather than being simulated in Python.
"""
import sys

from lupa import LuaError, LuaRuntime


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    script, root = sys.argv[1], sys.argv[2]
    with open(script, "r", encoding="utf-8") as fh:
        src = fh.read()

    literal = "[==[\n" + src.replace("]==]", "]==] ") + "\n]==]"
    driver = (
        "local f, e = (loadstring or load)(%s, %s)\n"
        "if not f then error(e, 0) end\n"
        "f(%s)\n" % (literal, repr("@" + script), repr(root))
    )

    rt = LuaRuntime(unpack_returned_tuples=True)
    try:
        rt.execute(driver)
    except LuaError as exc:
        print("[lua-error] %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
