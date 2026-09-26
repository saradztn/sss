from __future__ import annotations
from ..analyzers.base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding
from ..core.confidence import Confidence, Provenance
from ..core.context import AnalysisContext

class ComparatorAnalyzer(BaseAnalyzer):
    name = "compare"
    description = "مقارنة نتائج التحليل الثابت والديناميكي"
    version = "1.0.0"

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        res = self._result_shell()
        findings = []
        raw = {}

        imports = set(ctx.shared.get("imports", []))
        needed = set(ctx.shared.get("needed_libs", []))
        dynamic_raw = ctx.shared.get("dynamic_raw", {})
        strings_raw = ctx.shared.get("strings_raw", {})

        # Example comparison: static imports vs dynamic syscalls
        # If static shows network imports but dynamic shows no network, note discrepancy
        static_network = any("socket" in i.lower() or "connect" in i.lower() for i in imports) or any("socket" in s.lower() for s in strings_raw.get("urls", []))
        # also check behavior tags
        dynamic_network = bool(dynamic_raw.get("network_syscalls"))

        raw["static_network_hint"] = bool(static_network)
        raw["dynamic_network_observed"] = bool(dynamic_network)

        if static_network and not dynamic_network and dynamic_raw:
            findings.append(Finding(
                id="compare.network_discrepancy", category="comparison", title="تعارض شبكة: ثابت يشير لشبكة لكن الديناميكي لم يرصدها",
                description="الثابت وجد تلميحات شبكة لكن الديناميكي لم يرصد socket/connect. قد يكون المسار لم يُنفذ أو يحتاج مدخلات مختلفة.",
                confidence=Confidence.MEDIUM, provenance=Provenance.INFERRED,
                source="compare:static_vs_dynamic", method="imports vs strace",
                data=raw
            ))
        elif static_network and dynamic_network:
            findings.append(Finding(
                id="compare.network_consistent", category="comparison", title="توافق شبكة",
                description="الثابت والديناميكي متفقان على وجود نشاط شبكة",
                confidence=Confidence.HIGH, provenance=Provenance.INFERRED,
                source="compare:static_vs_dynamic", method="both indicate network",
                data=raw
            ))
        elif not static_network and not dynamic_network and dynamic_raw:
            findings.append(Finding(
                id="compare.no_network_consistent", category="comparison", title="توافق عدم وجود شبكة",
                description="لا يوجد دليل شبكة في الثابت ولا الديناميكي",
                confidence=Confidence.HIGH, provenance=Provenance.INFERRED,
                source="compare:static_vs_dynamic", method="negative both",
                data=raw
            ))

        # File access comparison
        static_paths = set(strings_raw.get("paths_sample", [])[:20])
        dynamic_files = set(dynamic_raw.get("accessed_files", [])[:20])
        overlap = static_paths.intersection(dynamic_files)
        raw["static_paths_sample"] = list(static_paths)[:10]
        raw["dynamic_files_sample"] = list(dynamic_files)[:10]
        raw["overlap"] = list(overlap)[:10]
        if overlap:
            findings.append(Finding(
                id="compare.file_overlap", category="comparison", title="تداخل مسارات ثابت/ديناميكي",
                description=f"{len(overlap)} مسار مشترك بين السلاسل الثابتة والوصول الديناميكي",
                confidence=Confidence.HIGH, provenance=Provenance.INFERRED,
                source="compare:file_overlap", method="set intersection",
                data={"overlap": list(overlap)[:10]}
            ))

        # Confidence synthesis
        findings.append(Finding(
            id="compare.methodology", category="comparison", title="منهجية المقارنة",
            description="المقارنة تزيد الثقة عند التوافق وتخفضها عند التعارض؛ كل تعارض يجب التحقيق بمدخلات إضافية.",
            confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
            source="compare:disclaimer", method="design",
            data=raw
        ))

        if not findings:
            findings.append(Finding(
                id="compare.insufficient", category="comparison", title="بيانات غير كافية للمقارنة",
                description="لا يوجد ديناميكي أو لا توجد تلميحات ثابتة كافية",
                confidence=Confidence.UNKNOWN, provenance=Provenance.UNDETERMINED,
                source="compare:empty", method="no data",
                data=raw
            ))

        ctx.store.save_json(f"evidence/{self.name}/raw.json", raw)
        ctx.shared["comparison_raw"] = raw
        res.findings = findings
        res.raw = raw
        return res
