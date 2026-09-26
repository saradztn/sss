"""
revspec.protection — منطق الحماية (جهة الدفاع).

هذا الحزمة لا تحتوي على أي قدرة تعديل أو تزوير. كل ما فيها يقرأ
سجلّات قراءات (readings) ويقرر: هل تغيّر معرّف العميل شرعي أم تزوير؟
"""
from .serial_consistency import (
    IdentifierClass,
    Reading,
    Transition,
    Verdict,
    SpoofReport,
    analyze_history,
    load_history,
)

__all__ = [
    "IdentifierClass",
    "Reading",
    "Transition",
    "Verdict",
    "SpoofReport",
    "analyze_history",
    "load_history",
]
