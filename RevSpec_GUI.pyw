#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# دبل كليك على هذا الملف لفتح الواجهة مباشرة (بدون كونسول)
import pathlib, sys
# === طلب مسؤول تلقائياً (لا ينهي نفسه إذا ألغى المستخدم) ===
if sys.platform == "win32" and "--no-admin" not in sys.argv and os.environ.get("REVSPEC_NO_ELEVATE") != "1":
    try:
        import ctypes, os
        if os.environ.get("__REVSPEC_ELEVATED") != "1" and ctypes.windll.shell32.IsUserAnAdmin() == 0:
            import os as _os
            _os.environ["__REVSPEC_ELEVATED"] = "1"
            params = " ".join([f'"{a}"' for a in sys.argv])
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            if ret > 32:
                sys.exit(0)
    except SystemExit:
        raise
    except: pass
# === نهاية ===
ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from gui.revspec_gui import main
if __name__ == "__main__":
    main()
