#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# دبل كليك على هذا الملف لفتح الواجهة مباشرة (بدون كونسول)
import pathlib, sys
# === طلب مسؤول تلقائياً ===
if sys.platform == "win32":
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            params = " ".join([f'"{a}"' for a in sys.argv])
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
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
