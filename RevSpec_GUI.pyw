#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# دبل كليك على هذا الملف لفتح الواجهة مباشرة (بدون كونسول)
import pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from gui.revspec_gui import main
if __name__ == "__main__":
    main()
