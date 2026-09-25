#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# دبل كليك لفتح Patcher بدون bat وبدون كونسول
import pathlib, sys, os
if 'idlelib' in sys.modules:
    import subprocess
    subprocess.Popen([sys.executable.replace('pythonw.exe','python.exe'), str(pathlib.Path(__file__).resolve())])
    sys.exit(0)
if sys.platform == "win32" and "--no-admin" not in sys.argv and os.environ.get("REVSPEC_NO_ELEVATE") != "1":
    try:
        import ctypes
        if os.environ.get("__REVSPEC_ELEVATED") != "1" and ctypes.windll.shell32.IsUserAnAdmin() == 0:
            os.environ["__REVSPEC_ELEVATED"] = "1"
            params = " ".join([f'"{a}"' for a in sys.argv])
            exe = sys.executable
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, f'"{__file__}"', None, 1)
            if ret > 32:
                sys.exit(0)
    except SystemExit:
        raise
    except: pass
ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from gui.patcher_gui import main
if __name__ == "__main__":
    main()
