"""
RevSpec — منصة هندسة عكسية معيارية
للاستخدام فقط على البرامج التي تملكها أو لديك تصريح بتحليلها.

The main package exposes version and the core Pipeline entry point.
"""
from __future__ import annotations

__version__ = "1.0.0"
__all__ = ["__version__"]

# Ethical guardrail import side-effect: print warning if used incorrectly
import sys as _sys
if _sys.argv and "revspec" in _sys.argv[0]:
    pass  # CLI will show disclaimer
