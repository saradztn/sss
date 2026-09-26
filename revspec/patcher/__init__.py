"""
RevSpec Patcher — نظام تعديل الثنائيات مثل Ghidra (للبرامج التي تملكها فقط)

يتيح:
- تغيير النصوص في البرنامج
- تغيير الاسم والـ metadata
- تعديل الواجهة (strings الخاصة بالـ UI)
- حفظ نسخة جديدة
"""
from .string_patcher import BinaryPatcher, StringEntry
from .pe_patcher import PEPatcher

__all__ = ["BinaryPatcher", "StringEntry", "PEPatcher"]
