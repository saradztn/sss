"""
serial_consistency — كشف تزوير معرّف العميل من سجلّ القراءات.

الفكرة
------
بدل محاولة منع تغيّر المعرّفات (مستحيل من جهة العميل)، نراقب **نمط** التغيّر
بين الجلسات. إعادة التثبيت الشرعية وأداة التزوير تتركان نمطين مختلفين:

    إعادة تثبيت / جهاز جديد : تتغيّر كل المعرّفات دفعة واحدة، أو تتغيّر
                              المراسي (BIOS/القرص/MAC) فعلاً.
    أداة تزوير              : تتغيّر المعرّفات الطيّعة فقط (MachineGuid،
                              SSO_RND_Device، قيم السجل) بينما تبقى المراسي
                              كما هي — لأن الأداة لا تستطيع تغيير العتاد.
    مسح متعمّد              : معرّف علامة (marker) يختفي ثم يظهر بقيمة جديدة.
    تزوير الاشتقاق          : الـ serial نفسه يتغيّر دون أن يتغيّر أي مدخل.

هذا الملف **لا يعدّل ولا يزوّر شيئاً**: مدخله سجلّ قراءات، ومخرجه حكم.

المرجع: الأنماط مشتقة من CSX.exe — انظر docs/client_lua_analysis.md
(يستخدم RegDeleteKeyA + CredDeleteW + MachineGuid + WMI SerialNumber
+ SSO_RND_Device).
"""
from __future__ import annotations

import dataclasses
import json
import pathlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence


class IdentifierClass(str, Enum):
    """تصنيف المعرّف حسب صعوبة تغييره **شرعياً**."""
    ANCHOR = "anchor"        # عتاد/تثبيت — لا يتغيّر إلا بعتاد جديد أو إعادة تثبيت
    VOLATILE = "volatile"    # قابل للتغيير من وضع المستخدم بلا أثر جانبي
    MARKER = "marker"        # طيّع + اختفاؤه بحد ذاته إشارة (يُولَّد عند أول تشغيل)


# المعرّفات المعروفة. أي معرّف غير مُدرَج يُعامل كـ VOLATILE (الأسوأ افتراضاً).
IDENTIFIER_CLASSES: Dict[str, IdentifierClass] = {
    # مراسي — تتغيّر فقط بعتاد جديد أو إعادة تثبيت فعلية
    "bios_serial":   IdentifierClass.ANCHOR,
    "board_serial":  IdentifierClass.ANCHOR,
    "disk_serial":   IdentifierClass.ANCHOR,
    "mac_address":   IdentifierClass.ANCHOR,
    "install_date":  IdentifierClass.ANCHOR,
    # طيّعة — تُكتب/تُحذف من وضع المستخدم
    "machine_guid":  IdentifierClass.VOLATILE,
    "volume_serial": IdentifierClass.VOLATILE,
    "product_id":    IdentifierClass.VOLATILE,
    "computer_name": IdentifierClass.VOLATILE,
    "user_name":     IdentifierClass.VOLATILE,
    # علامات — يولّدها البرنامج نفسه، فحذفها ثم إعادة توليدها = إعادة ضبط متعمّدة
    "sso_rnd_device": IdentifierClass.MARKER,
    "mta_serial":     IdentifierClass.MARKER,
    "mta_owner":      IdentifierClass.MARKER,
}


def classify(key: str) -> IdentifierClass:
    return IDENTIFIER_CLASSES.get(key, IdentifierClass.VOLATILE)


class Verdict(str, Enum):
    CONSISTENT = "consistent"                    # لا تغيّر
    LEGIT_CHANGE = "legit-change"                # إعادة تثبيت / جهاز جديد
    HARDWARE_CHANGE = "hardware-change"          # تغيّر مراسي فعلية
    SPOOF_PARTIAL = "spoof-partial"              # طيّع تغيّر والمراسي ثابتة
    SPOOF_RESET = "spoof-reset"                  # علامة حُذفت ثم أعيد توليدها
    DERIVATION_TAMPER = "derivation-tamper"      # الـ serial تغيّر والمدخلات لم تتغيّر
    INSUFFICIENT_DATA = "insufficient-data"


# ترتيب الخطورة — يُستخدم لاختيار أسوأ انتقال في التقرير الكلي
_SEVERITY = {
    Verdict.DERIVATION_TAMPER: 5,
    Verdict.SPOOF_RESET: 4,
    Verdict.SPOOF_PARTIAL: 3,
    Verdict.HARDWARE_CHANGE: 2,
    Verdict.LEGIT_CHANGE: 1,
    Verdict.CONSISTENT: 0,
    Verdict.INSUFFICIENT_DATA: 0,
}


@dataclass
class Reading:
    """قراءة واحدة من جلسة واحدة."""
    session_id: str
    timestamp: str
    # اسم المعرّف -> قيمته. القيمة None أو غائبة تعني "غير قابل للقراءة/غير موجود".
    identifiers: Dict[str, Optional[str]] = field(default_factory=dict)
    # الـ serial الذي اشتقّه العميل في هذه الجلسة (اختياري)
    client_serial: Optional[str] = None

    @staticmethod
    def from_dict(d: Dict) -> "Reading":
        return Reading(
            session_id=str(d.get("session_id", "")),
            timestamp=str(d.get("timestamp", "")),
            identifiers=dict(d.get("identifiers", {}) or {}),
            client_serial=d.get("client_serial"),
        )

    def value(self, key: str) -> Optional[str]:
        v = self.identifiers.get(key)
        if v is None:
            return None
        v = str(v)
        return v if v != "" else None


@dataclass
class Transition:
    """حكم على التغيّر بين قراءتين متتاليتين."""
    from_session: str
    to_session: str
    # تغيّر قيمة فعلي (كانت القيمة موجودة في القراءتين واختلفت)
    changed: List[str] = field(default_factory=list)
    anchors_changed: List[str] = field(default_factory=list)
    volatiles_changed: List[str] = field(default_factory=list)
    markers_changed: List[str] = field(default_factory=list)
    # تغيّر توفّر فقط (لا قيمة قديمة للمقارنة) — ليس دليلاً على تلاعب
    appeared: List[str] = field(default_factory=list)
    disappeared: List[str] = field(default_factory=list)
    # علامة كانت موجودة، اختفت، ثم عادت بقيمة مختلفة
    reappeared_changed: List[str] = field(default_factory=list)
    serial_changed: bool = False
    verdict: Verdict = Verdict.CONSISTENT
    confidence: float = 0.0
    reasons: List[str] = field(default_factory=list)

    @property
    def severity(self) -> int:
        return _SEVERITY[self.verdict]

    def to_dict(self) -> Dict:
        d = dataclasses.asdict(self)
        d["verdict"] = self.verdict.value
        d["severity"] = self.severity
        return d


@dataclass
class SpoofReport:
    """التقرير الكلي على سجلّ قراءات."""
    readings: int
    transitions: List[Transition] = field(default_factory=list)
    worst_verdict: Verdict = Verdict.INSUFFICIENT_DATA
    worst_confidence: float = 0.0
    action: str = "allow"
    summary: str = ""

    def to_dict(self) -> Dict:
        return {
            "readings": self.readings,
            "transitions": [t.to_dict() for t in self.transitions],
            "worst_verdict": self.worst_verdict.value,
            "worst_confidence": self.worst_confidence,
            "action": self.action,
            "summary": self.summary,
        }


# نسبة المعرّفات التي يجب أن تتغيّر معاً ليُعتبر التغيّر "جهاز جديد/إعادة تثبيت"
FULL_CHANGE_RATIO = 0.8


def _diff(prev: Reading, curr: Reading) -> Dict[str, List[str]]:
    """
    يفرّق بين ثلاثة أشياء مختلفة:

    1. **تغيّر قيمة فعلي** — القيمة كانت موجودة في القراءتين واختلفت.
       هذا وحده دليل على تلاعب محتمل.
    2. **ظهور** — لم يكن مقروءاً ثم صار. لا توجد قيمة قديمة للمقارنة،
       فلا يُحسب تغيّراً (وإلا صار فشل قراءة BIOS = "تغيير عتاد").
    3. **اختفاء** — كان مقروءاً ثم لم يعد. مهم للعلامات (MARKER) لأنه
       النصف الأول من نمط الحذف-ثم-إعادة-التوليد.
    """
    keys = set(prev.identifiers) | set(curr.identifiers)
    out = {"changed": [], "anchors": [], "volatiles": [], "markers": [],
           "appeared": [], "disappeared": []}
    for k in sorted(keys):
        a, b = prev.value(k), curr.value(k)
        if a == b:
            continue
        if a is None:
            out["appeared"].append(k)
            continue
        if b is None:
            out["disappeared"].append(k)
            continue
        # من هنا: تغيّر قيمة فعلي
        out["changed"].append(k)
        cls = classify(k)
        if cls is IdentifierClass.ANCHOR:
            out["anchors"].append(k)
        elif cls is IdentifierClass.MARKER:
            out["markers"].append(k)
        else:
            out["volatiles"].append(k)
    return out


def _detect_reset(prev_prev: Optional[Reading], prev: Reading, curr: Reading) -> List[str]:
    """علامة كانت موجودة، اختفت، ثم عادت بقيمة مختلفة = إعادة ضبط متعمّدة."""
    if prev_prev is None:
        return []
    keys = set(prev_prev.identifiers) | set(prev.identifiers) | set(curr.identifiers)
    hits = []
    for k in sorted(keys):
        if classify(k) is not IdentifierClass.MARKER:
            continue
        a, b, c = prev_prev.value(k), prev.value(k), curr.value(k)
        if a is not None and b is None and c is not None and a != c:
            hits.append(k)
    return hits


def evaluate_transition(prev: Reading, curr: Reading,
                        prev_prev: Optional[Reading] = None) -> Transition:
    """يطبّق القواعد على انتقال واحد. القواعد مرتبة من الأشد إلى الأخف."""
    d = _diff(prev, curr)
    reappeared = _detect_reset(prev_prev, prev, curr)

    t = Transition(
        from_session=prev.session_id, to_session=curr.session_id,
        changed=d["changed"], anchors_changed=d["anchors"],
        volatiles_changed=d["volatiles"], markers_changed=d["markers"],
        appeared=d["appeared"], disappeared=d["disappeared"],
        reappeared_changed=reappeared,
        serial_changed=(prev.client_serial is not None
                        and curr.client_serial is not None
                        and prev.client_serial != curr.client_serial),
    )

    # 1) الـ serial تغيّر والمدخلات لم تتغيّر → الاشتقاق نفسه مُلاعَب به.
    #    نستثني حالة reappeared: هناك تغيّر serial **مُفسَّر** بإعادة ضبط
    #    المدخلات، فتُترك للقاعدة 2 بدل وسمها كتلاعب بالاشتقاق.
    if t.serial_changed and not t.changed and not reappeared:
        t.verdict = Verdict.DERIVATION_TAMPER
        t.confidence = 0.95
        t.reasons.append(
            "client_serial تغيّر دون أي تغيّر في المعرّفات — الاشتقاق مُلاعَب به "
            "أو القيمة المخزّنة عُدّلت مباشرة")

    # 2) علامة حُذفت ثم أُعيد توليدها بقيمة جديدة → إعادة ضبط متعمّدة
    if reappeared:
        t.verdict = Verdict.SPOOF_RESET
        t.confidence = 0.9
        t.reasons.append(
            "المعرّفات العلامة اختفت ثم عادت بقيم جديدة: "
            + ", ".join(reappeared)
            + " — هذا نمط حذف-ثم-إعادة-توليد، لا إعادة تثبيت")

    # 3) الطيّع تغيّر والمراسي ثابتة → توقيع أداة تزوير
    if t.volatiles_changed and not t.anchors_changed:
        t.verdict = Verdict.SPOOF_PARTIAL
        t.confidence = 0.85
        t.reasons.append(
            "تغيّرت المعرّفات الطيّعة فقط (" + ", ".join(t.volatiles_changed)
            + ") بينما بقيت كل المراسي المتاحة ("
            + (", ".join(sorted(_anchor_keys(prev, curr))) or "لا شيء")
            + ") ثابتة. تغيير العتاد الحقيقي يغيّر المراسي.")

    # 4) المراسي تغيّرت فعلاً → تغيير عتاد/إعادة تثبيت محتمل
    if t.anchors_changed and t.verdict not in (
            Verdict.DERIVATION_TAMPER, Verdict.SPOOF_RESET, Verdict.SPOOF_PARTIAL):
        t.verdict = Verdict.HARDWARE_CHANGE
        t.confidence = 0.5
        t.reasons.append(
            "تغيّرت مراسي فعلية: " + ", ".join(t.anchors_changed)
            + " — يتوافق مع تغيير عتاد أو إعادة تثبيت")

    # 5) كل شيء تغيّر دفعة واحدة → جهاز جديد / إعادة تثبيت
    if t.changed:
        available = _available_keys(prev, curr)
        ratio = len(t.changed) / len(available) if available else 0.0
        if ratio >= FULL_CHANGE_RATIO and t.verdict not in (
                Verdict.DERIVATION_TAMPER, Verdict.SPOOF_RESET, Verdict.SPOOF_PARTIAL):
            t.verdict = Verdict.LEGIT_CHANGE
            t.confidence = 0.6
            t.reasons.append(
                f"{len(t.changed)}/{len(available)} من المعرّفات تغيّرت معاً "
                f"(≥{int(FULL_CHANGE_RATIO*100)}%) — نمط جهاز جديد أو إعادة تثبيت")

    # 6) لا تغيّر قيمة فعلي ولا تغيّر serial
    if not t.changed and not t.serial_changed:
        if t.verdict is Verdict.CONSISTENT:
            t.confidence = 0.9
            t.reasons.append("لا تغيّر قيمة في أي معرّف ولا في client_serial")

    # ملاحظات لا تغيّر الحكم بنفسها (تُسجَّل للمراجعة)
    if t.disappeared and not reappeared:
        t.reasons.append(
            "ملاحظة: اختفت معرّفات ولم تعد في هذه النافذة: "
            + ", ".join(t.disappeared)
            + " — النصف الأول من نمط إعادة الضبط؛ الحكم النهائي يحتاج الجلسة التالية")
    if t.appeared:
        t.reasons.append(
            "ملاحظة: صارت هذه مقروءة بعد غياب (لا قيمة قديمة للمقارنة، "
            "فلا تُحسب تغيّراً): " + ", ".join(t.appeared))

    return t


def _available_keys(prev: Reading, curr: Reading) -> set:
    return {k for k in (set(prev.identifiers) | set(curr.identifiers))
            if prev.value(k) is not None or curr.value(k) is not None}


def _anchor_keys(prev: Reading, curr: Reading) -> set:
    return {k for k in _available_keys(prev, curr)
            if classify(k) is IdentifierClass.ANCHOR}


def analyze_history(readings: Sequence[Reading]) -> SpoofReport:
    """يحلّل سجلّ قراءات مرتّباً زمنياً ويخرج تقريراً."""
    report = SpoofReport(readings=len(readings))
    if len(readings) < 2:
        report.summary = "قراءة واحدة أو أقل — لا يمكن الحكم على التغيّر"
        report.action = "insufficient-data"
        return report

    for i in range(1, len(readings)):
        prev_prev = readings[i - 2] if i >= 2 else None
        report.transitions.append(
            evaluate_transition(readings[i - 1], readings[i], prev_prev))

    worst = max(report.transitions, key=lambda t: (t.severity, t.confidence))
    report.worst_verdict = worst.verdict
    report.worst_confidence = worst.confidence
    report.action = _action_for(worst.verdict, worst.confidence)
    report.summary = (
        f"{len(report.transitions)} انتقال؛ الأسوأ = {worst.verdict.value} "
        f"بثقة {worst.confidence:.2f} ({worst.from_session} → {worst.to_session})"
    )
    return report


def _action_for(verdict: Verdict, confidence: float) -> str:
    """إجراء مقترح لجهة الحماية — قرار سياسة، قابل للضبط عندك."""
    if verdict is Verdict.DERIVATION_TAMPER:
        return "block"
    if verdict is Verdict.SPOOF_RESET:
        return "block" if confidence >= 0.8 else "require-reauth"
    if verdict is Verdict.SPOOF_PARTIAL:
        return "require-reauth" if confidence >= 0.8 else "flag"
    if verdict is Verdict.HARDWARE_CHANGE:
        return "require-reauth"
    if verdict is Verdict.LEGIT_CHANGE:
        return "allow-with-note"
    if verdict is Verdict.INSUFFICIENT_DATA:
        return "insufficient-data"
    return "allow"


def load_history(path) -> List[Reading]:
    """
    يقرأ سجلّ قراءات من JSON:
        {"readings": [{"session_id": "...", "timestamp": "...",
                       "identifiers": {...}, "client_serial": "..."}]}
    أو قائمة مباشرة.
    """
    p = pathlib.Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    items = data.get("readings", data) if isinstance(data, dict) else data
    return [Reading.from_dict(d) for d in items]
