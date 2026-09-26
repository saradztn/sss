"""
مستويات الثقة + تصنيف المصدر

كل استنتاج يجب أن يحمل:
- confidence: مدى الثقة
- provenance: هل هو مثبت أم مستنتج
- source: الأداة/الطريقة
- evidence_ref: مرجع للدليل الخام
"""
from __future__ import annotations
from enum import Enum

class Confidence(str, Enum):
    PROVEN = "proven"           # تم إثباته بملاحظة مباشرة (مثلاً hash محسوب، syscall مرصود)
    HIGH = "high"               # استنتاج قوي جداً مع أدلة متعددة متسقة
    MEDIUM = "medium"           # استنتاج معقول لكن بدليل واحد أو غير مكتمل
    LOW = "low"                 # تخمين ضعيف، يحتاج تأكيد
    SPECULATIVE = "speculative" # تخمين مبني على heuristics فقط
    UNKNOWN = "unknown"         # تعذر التحديد

    def numeric(self) -> float:
        return {
            Confidence.PROVEN: 1.0,
            Confidence.HIGH: 0.85,
            Confidence.MEDIUM: 0.6,
            Confidence.LOW: 0.35,
            Confidence.SPECULATIVE: 0.15,
            Confidence.UNKNOWN: 0.0,
        }[self]

class Provenance(str, Enum):
    OBSERVED = "observed"       # حقيقة مرصودة مباشرة (proven)
    INFERRED = "inferred"       # استنتاج
    ABSENT = "absent"           # لم يتم العثور عليه / غير موجود
    UNDETERMINED = "undetermined" # تعذر التحديد

# Helper to decide provenance from confidence
def provenance_for(conf: Confidence) -> Provenance:
    if conf == Confidence.PROVEN:
        return Provenance.OBSERVED
    if conf == Confidence.UNKNOWN:
        return Provenance.UNDETERMINED
    return Provenance.INFERRED
