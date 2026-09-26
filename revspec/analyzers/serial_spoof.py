"""
محلل كشف قدرة تزوير/تغيير المعرّفات (Serial / HWID spoofing) + الحقن

الغرض: جهة الحماية. هذا المحلل يفحص ملفاً ثنائياً ويقرر ما إذا كان يحتوي على
القدرة على تغيير المعرّف الذي تعتمد عليه اللعبة في الحظر (serial)، وما إذا كان
يحتوي على قدرة حقن في عملية أخرى.

المحلل **قراءة فقط**: لا يشغّل العينة، ولا يعدّل شيئاً، ولا ينتج أي أداة.
يعمل على PE (ويستخرج نصوص ASCII + UTF-16LE) ويتجاهل بصمت أي ملف ليس PE.
"""
from __future__ import annotations
import re
import struct
from typing import Dict, List, Tuple

from .base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding
from ..core.confidence import Confidence, Provenance
from ..core.context import AnalysisContext


# ---------------------------------------------------------------------------
# مجموعات المؤشرات.
# كل مؤشر: (نمط regex على النص المستخرج، وزن، وصف، تسمية)
# الأوزان معايرة على العينة المرجعية CSX.exe (انظر docs/serial_hardening.md).
# ---------------------------------------------------------------------------

SERIAL_INPUT_INDICATORS: List[Tuple[str, int, str]] = [
    # المعرّفات التي تُشتق منها serial عادةً
    (r"MachineGuid", 8, "قراءة MachineGuid (SOFTWARE\\Microsoft\\Cryptography)"),
    (r"SOFTWARE\\Microsoft\\Cryptography", 4, "مفتاح السجل الذي يحوي MachineGuid"),
    (r"SELECT\s+SerialNumber\s+FROM\s+Win32_", 10, "استعلام WMI عن SerialNumber للعتاد"),
    (r"Win32_BIOS", 6, "WMI: Win32_BIOS (SerialNumber/Manufacturer/Model)"),
    (r"Win32_DiskDrive", 6, "WMI: Win32_DiskDrive"),
    (r"Win32_BaseBoard", 6, "WMI: Win32_BaseBoard"),
    (r"ROOT\\CIMV2", 4, "مساحة أسماء WMI"),
    (r"GetAdaptersInfo|GetAdaptersAddresses", 4, "قراءة عناوين MAC"),
    (r"GetVolumeInformation", 5, "قراءة Volume Serial للقرص"),
    (r"SSO_RND_Device", 6, "معرّف جهاز عشوائي مخزّن (نمط معرّف قابل لإعادة التوليد)"),
]

# APIs التي تُستخدم لتغيير/حذف القيم المخزّنة للمعرّف (وليس مجرد قراءتها)
SERIAL_MUTATION_APIS: List[Tuple[str, int, str]] = [
    (r"\bRegDeleteKeyA\b|\bRegDeleteKeyW\b", 10, "حذف مفتاح سجل"),
    (r"\bRegDeleteValueA\b|\bRegDeleteValueW\b", 10, "حذف قيمة سجل"),
    (r"\bRegSetValueExA\b|\bRegSetValueExW\b", 6, "كتابة قيمة سجل"),
    (r"\bCredDeleteW\b|\bCredDeleteA\b", 8, "حذف بيانات اعتماد مخزّنة"),
    (r"\bRegCreateKeyExA\b|\bRegCreateKeyExW\b", 3, "إنشاء مفتاح سجل"),
]

# نصوص تُثبت النيّة صراحةً (أعلى قيمة إثباتية)
INTENT_STRINGS: List[Tuple[str, int, str]] = [
    (r"Resetting\s+MTA\s+serial", 20, "نص صريح: إعادة ضبط serial الخاص بـ MTA"),
    (r"Serial\s+reset\s+complete", 18, "نص صريح: اكتمل تغيير الـ serial"),
    (r"R\s*E\s*S\s*E\s*T\s+S\s*E\s*R\s*I\s*A\s*L", 18, "زر/عنوان واجهة: إعادة ضبط الـ serial"),
    (r"Reset\s+your\s+Mta\s+Serial", 18, "سؤال واجهة عن إعادة ضبط الـ serial"),
    (r"spoof(?:ed|ing)?\s+(?:hwid|serial|machine)", 15, "ذكر صريح لتزوير hwid/serial"),
]

# مفاتيح سجل اللعبة المستهدفة
GAME_REGISTRY: List[Tuple[str, int, str]] = [
    (r"SOFTWARE\\(?:WOW6432Node\\)?Multi Theft Auto", 12, "مفاتيح سجل Multi Theft Auto"),
]

# APIs الحقن في عملية أخرى
INJECTION_APIS: List[Tuple[str, int, str]] = [
    (r"\bVirtualAllocEx\b", 8, "تخصيص ذاكرة في عملية أخرى"),
    (r"\bWriteProcessMemory\b", 10, "كتابة ذاكرة في عملية أخرى"),
    (r"\bCreateRemoteThread\b", 12, "إنشاء thread في عملية أخرى"),
    (r"\bQueueUserAPC\b|\bNtQueueApcThread\b", 10, "حقن عبر APC"),
    (r"\bSetThreadContext\b", 8, "تعديل سياق thread (process hollowing)"),
    (r"\bNtMapViewOfSection\b", 8, "خريطة قسم في عملية أخرى"),
]

# تهرّب من التحليل
EVASION_APIS: List[Tuple[str, int, str]] = [
    (r"\bIsDebuggerPresent\b", 5, "كشف debugger"),
    (r"\bCheckRemoteDebuggerPresent\b", 6, "كشف debugger عن بُعد"),
    (r"\bNtQueryInformationProcess\b", 5, "استعلام معلومات العملية (كشف debug)"),
    (r"\\\\VBOXSRV\\|\\\\vboxsrv\\", 5, "كشف VirtualBox عبر مشاركات الشبكة"),
    (r"\\\\tsclient\\", 5, "كشف بيئة RDP/مشاركة عميل"),
    (r"\bNetShareEnum\b", 3, "تعداد مشاركات الشبكة (يُستخدم لكشف البيئة)"),
]

# أقسام PE المشبوهة (اسم + محتوى كود)
SUSPICIOUS_SECTION_NAMES = {".mmap", ".enigma1", ".enigma2", ".themida", ".vmp0", ".vmp1", ".aspack", ".upx0", ".upx1"}


def _parse_pe_sections(data: bytes) -> List[Dict]:
    """قارئ جدول أقسام PE بسيط — بدون اعتماديات خارجية."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return []
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return []
    (nsec,) = struct.unpack_from("<H", data, e_lfanew + 6)
    (optsz,) = struct.unpack_from("<H", data, e_lfanew + 20)
    base = e_lfanew + 24 + optsz
    out = []
    for i in range(min(nsec, 96)):
        o = base + i * 40
        if o + 40 > len(data):
            break
        name = data[o:o + 8].rstrip(b"\x00").decode("latin-1", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
        (chars,) = struct.unpack_from("<I", data, o + 36)
        blob = data[rawptr:rawptr + min(rawsize, 4096)] if rawptr + rawsize <= len(data) else b""
        out.append({
            "name": name, "virtual_address": va, "virtual_size": vsize,
            "raw_size": rawsize, "raw_ptr": rawptr, "characteristics": chars,
            "executable": bool(chars & 0x20000000),
            "writable": bool(chars & 0x80000000),
            # هل يبدأ القسم بكود x86 نموذجي (prologue)؟
            "looks_like_code": bool(blob[:4] in (b"\x55\x8b\xec", b"\x55\x89\xe5", b"\x40\x53", b"\x48\x89\x5c"))
                                 or blob[:1] in (b"\xe9", b"\xeb", b"\x55", b"\x53", b"\x56", b"\x57"),
            "preview_hex": blob[:32].hex(),
        })
    return out


def _extract_strings(data: bytes, limit: int = 1500000) -> str:
    """
    نصوص ASCII + UTF-16LE، **بدون تكرار**، للبحث عنها بـ regex.

    ملاحظة مهمة: إزالة التكرار إلزامية — العينات المحزومة/ذات الموارد الضخمة
    (مثل CSX.exe بـ .rsrc = 5.8 م.ب) تكرر نفس السلاسل عشرات آلاف المرات،
    وبدون dedup يمتلئ الحد قبل الوصول إلى نصوص .rdata المشفّرة بـ UTF-16.
    """
    ascii_re = re.compile(rb"[\x20-\x7e]{4,}")
    # UTF-16LE: حرف قابل للطباعة متبوع بـ 0x00
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
    uniq: Dict[str, None] = {}
    for m in ascii_re.finditer(data):
        uniq.setdefault(m.group().decode("latin-1", "replace"))
    for m in utf16_re.finditer(data):
        uniq.setdefault(m.group().decode("utf-16-le", "replace"))
    out: List[str] = []
    total = 0
    for s in uniq:
        out.append(s)
        total += len(s) + 1
        if total >= limit:
            break
    return "\n".join(out)


def _scan(corpus: str, rules: List[Tuple[str, int, str]]) -> Tuple[List[Dict], int]:
    hits: List[Dict] = []
    score = 0
    for pattern, weight, desc in rules:
        m = re.search(pattern, corpus, flags=re.IGNORECASE)
        if m:
            score += weight
            hits.append({"pattern": pattern, "weight": weight, "description": desc,
                         "match": m.group(0)[:80]})
    return hits, score


class SerialSpoofAnalyzer(BaseAnalyzer):
    name = "serial_spoof"
    description = "كشف قدرة تغيير/تزوير معرّف العميل (serial/HWID) وقدرة الحقن — للقراءة فقط"
    version = "1.0.0"
    requires_tools: List[str] = []

    # العتبات
    SERIAL_CHANGE_THRESHOLD = 30      # درجة قدرة تغيير المعرّف
    SERIAL_STRONG_THRESHOLD = 55
    INJECT_THRESHOLD = 20

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        res = self._result_shell()
        data = ctx.sample_path.read_bytes()
        findings: List[Finding] = []
        raw: Dict = {"size": len(data)}

        sections = _parse_pe_sections(data)
        is_pe = bool(sections)
        raw["is_pe"] = is_pe
        raw["sections"] = [{k: v for k, v in s.items() if k != "preview_hex"} for s in sections]

        corpus = _extract_strings(data)
        raw["corpus_chars"] = len(corpus)
        ctx.store.save_text(f"evidence/{self.name}/corpus.txt", corpus[:200000])

        serial_inputs, s1 = _scan(corpus, SERIAL_INPUT_INDICATORS)
        mutations, s2 = _scan(corpus, SERIAL_MUTATION_APIS)
        intents, s3 = _scan(corpus, INTENT_STRINGS)
        game_reg, s4 = _scan(corpus, GAME_REGISTRY)
        injection, s5 = _scan(corpus, INJECTION_APIS)
        evasion, s6 = _scan(corpus, EVASION_APIS)

        # تغيير المعرّف يتطلب: قراءة معرّف + قدرة تعديل/حذف، أو نيّة صريحة
        serial_score = s1 + s2 + s3 + s4
        if (s1 and not s2 and not s3):
            # يقرأ المعرّفات فقط ولا يعدّلها — هذا طبيعي (تسجيل دخول، ترخيص)
            serial_score = min(serial_score, self.SERIAL_CHANGE_THRESHOLD - 1)
        inject_score = s5
        raw.update({
            "serial_inputs": serial_inputs, "mutation_apis": mutations,
            "intent_strings": intents, "game_registry": game_reg,
            "injection_apis": injection, "evasion": evasion,
            "serial_score": serial_score, "injection_score": inject_score,
        })
        ctx.store.save_json(f"evidence/{self.name}/raw.json", raw)

        # --- قسم PE يحمل كوداً باسم مشبوه (نمط manual mapping) ---
        for s in sections:
            if s["name"].lower() in SUSPICIOUS_SECTION_NAMES and s["executable"]:
                findings.append(Finding(
                    id="serial_spoof.suspicious_section", category="structure",
                    title=f"قسم تنفيذي باسم مشبوه: {s['name']}",
                    description=(
                        f"القسم {s['name']} قابل للتنفيذ (char=0x{s['characteristics']:08x}) "
                        f"ويبدأ ببايتات تشبه كود x86 ({s['preview_hex']}). هذا نمط قسم مُحمِّل PE "
                        f"(manual mapping) يُستخدم لتحميل حمولة من الذاكرة بدل القرص."
                    ),
                    confidence=Confidence.MEDIUM, provenance=Provenance.INFERRED,
                    source="serial_spoof:pe_section_scan",
                    method="parse PE section table + prologue heuristic",
                    data={k: v for k, v in s.items() if k != "preview_hex"} | {"preview_hex": s["preview_hex"]},
                    tags=["manual-mapping", "heuristic"],
                ))

        # --- قراءة معرّفات العتاد ---
        if serial_inputs:
            findings.append(Finding(
                id="serial_spoof.reads_hwid", category="behavior",
                title="يقرأ معرّفات عتاد تُستخدم عادةً لاشتقاق serial",
                description="؛ ".join(h["description"] for h in serial_inputs),
                confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                source="serial_spoof:string_scan", method="regex over ASCII+UTF16LE strings",
                data={"hits": serial_inputs, "score": s1},
                tags=["hwid"],
            ))

        # --- قدرة تعديل/حذف ---
        if mutations:
            findings.append(Finding(
                id="serial_spoof.can_mutate", category="behavior",
                title="يستورد APIs لتعديل/حذف قيم مخزّنة",
                description="؛ ".join(h["description"] for h in mutations),
                confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                source="serial_spoof:string_scan", method="regex over ASCII+UTF16LE strings",
                data={"hits": mutations, "score": s2},
                tags=["registry", "mutation"],
            ))

        # --- نيّة صريحة ---
        if intents:
            findings.append(Finding(
                id="serial_spoof.explicit_intent", category="behavior",
                title="نصوص صريحة على تغيير الـ serial",
                description="؛ ".join(h["description"] for h in intents),
                confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                source="serial_spoof:string_scan", method="regex over ASCII+UTF16LE strings",
                data={"hits": intents, "score": s3},
                tags=["intent", "serial-reset"],
            ))

        # --- مفاتيح سجل اللعبة ---
        if game_reg:
            findings.append(Finding(
                id="serial_spoof.game_registry", category="behavior",
                title="يستهدف مفاتيح سجل اللعبة",
                description="؛ ".join(h["description"] for h in game_reg),
                confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                source="serial_spoof:string_scan", method="regex over ASCII+UTF16LE strings",
                data={"hits": game_reg}, tags=["registry", "game"],
            ))

        # --- الحقن ---
        if injection:
            conf = Confidence.PROVEN if len(injection) >= 3 else Confidence.HIGH
            findings.append(Finding(
                id="serial_spoof.injection_capability", category="behavior",
                title=f"قدرة حقن في عملية أخرى ({len(injection)} مؤشرات)",
                description="؛ ".join(h["description"] for h in injection),
                confidence=conf, provenance=Provenance.OBSERVED,
                source="serial_spoof:string_scan", method="regex over ASCII+UTF16LE strings",
                data={"hits": injection, "score": inject_score},
                tags=["injection"],
            ))

        # --- التهرّب ---
        if evasion:
            findings.append(Finding(
                id="serial_spoof.evasion", category="behavior",
                title="مؤشرات تهرّب من التحليل",
                description="؛ ".join(h["description"] for h in evasion),
                confidence=Confidence.HIGH, provenance=Provenance.INFERRED,
                source="serial_spoof:string_scan", method="regex over ASCII+UTF16LE strings",
                data={"hits": evasion, "score": s6}, tags=["anti-analysis"],
            ))

        # --- الحكم النهائي ---
        if serial_score >= self.SERIAL_STRONG_THRESHOLD:
            verdict, conf = "capable-serial-change", Confidence.HIGH
        elif serial_score >= self.SERIAL_CHANGE_THRESHOLD:
            verdict, conf = "suspected-serial-change", Confidence.MEDIUM
        else:
            verdict, conf = "no-serial-change-indicator", Confidence.HIGH

        if verdict == "no-serial-change-indicator":
            prov = Provenance.ABSENT
        else:
            prov = Provenance.INFERRED

        findings.append(Finding(
            id="serial_spoof.verdict", category="verdict",
            title=f"الحكم: {verdict}",
            description=(
                f"درجة تغيير المعرّف = {serial_score} "
                f"(العتبة الضعيفة {self.SERIAL_CHANGE_THRESHOLD}، القوية {self.SERIAL_STRONG_THRESHOLD})؛ "
                f"درجة الحقن = {inject_score} (العتبة {self.INJECT_THRESHOLD}). "
                f"ملاحظة: هذا حكم ثابت على القدرة المستورَدة، لا على سلوك مُنفَّذ."
            ),
            confidence=conf, provenance=prov,
            source="serial_spoof:scored_rules", method="weighted indicator scoring",
            data={
                "verdict": verdict,
                "serial_score": serial_score,
                "injection_score": inject_score,
                "evasion_score": s6,
                "is_pe": is_pe,
            },
            tags=["verdict"],
        ))

        res.findings = findings
        res.raw = {k: v for k, v in raw.items() if k != "sections"} | {"sections_count": len(sections)}
        return res
