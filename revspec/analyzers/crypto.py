from __future__ import annotations
import math
import collections

from .base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding
from ..core.confidence import Confidence, Provenance
from ..core.context import AnalysisContext

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = collections.Counter(data)
    ent = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent

class CryptoAnalyzer(BaseAnalyzer):
    name = "crypto"
    description = "كشف التشفير/الضغط/الحزم عبر الإنتروبي وثوابت معروفة"
    version = "1.0.0"

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        res = self._result_shell()
        p = ctx.sample_path
        raw = {}
        findings = []

        data = p.read_bytes()
        # overall entropy
        overall = entropy(data)
        raw["overall_entropy"] = round(overall, 4)
        raw["size"] = len(data)

        # sliding window entropy (1KB windows)
        win = 1024
        high_windows = 0
        windows = []
        for i in range(0, len(data), win):
            chunk = data[i:i+win]
            e = entropy(chunk)
            windows.append(e)
            if e > 7.5:
                high_windows += 1
        raw["high_entropy_windows"] = high_windows
        raw["total_windows"] = len(windows)
        raw["avg_window_entropy"] = round(sum(windows)/len(windows),4) if windows else 0
        raw["max_window_entropy"] = round(max(windows),4) if windows else 0

        # crypto constants
        constants = []
        # AES S-box, etc. simple heuristics: search for known byte sequences
        # e.g., AES S-box first 16 bytes: 63 7c 77 7b f2 6b 6f c5 ...
        aes_sbox = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
        if aes_sbox in data:
            constants.append("AES S-box")
        # Check for base64 alphabet
        if b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" in data:
            constants.append("base64 alphabet")
        # Check for common strings: "BEGIN CERTIFICATE"
        if b"BEGIN CERTIFICATE" in data:
            constants.append("PEM certificate marker")
        if b"BEGIN PRIVATE KEY" in data or b"BEGIN RSA PRIVATE KEY" in data:
            constants.append("PEM private key marker")

        raw["constants_found"] = constants

        ctx.store.save_json(f"evidence/{self.name}/raw.json", raw)
        # save entropy graph data
        ctx.store.save_json(f"evidence/{self.name}/entropy_windows.json", {"windows": windows[:500]})

        # findings
        # entropy interpretation
        if overall > 7.2:
            findings.append(Finding(
                id="crypto.high_entropy", category="crypto", title="إنتروبي عالي — محتمل تشفير/ضغط/حزم",
                description=f"إنتروبي كلي {overall:.2f} (>7.2) يشير لاحتمال تشفير أو ضغط أو packer",
                confidence=Confidence.MEDIUM, provenance=Provenance.INFERRED,
                source="crypto:entropy", method="shannon entropy",
                data={"overall_entropy": overall, "high_windows": high_windows},
                tags=["heuristic"]
            ))
        elif overall < 5.0:
            findings.append(Finding(
                id="crypto.low_entropy", category="crypto", title="إنتروبي منخفض — نص/كود غير مضغوط",
                description=f"إنتروبي {overall:.2f} منخفض يشير لملف غير مشفر/غير مضغوط",
                confidence=Confidence.MEDIUM, provenance=Provenance.INFERRED,
                source="crypto:entropy", method="shannon",
                data={"overall_entropy": overall}
            ))
        else:
            findings.append(Finding(
                id="crypto.normal_entropy", category="crypto", title="إنتروبي متوسط",
                description=f"إنتروبي {overall:.2f} متوسط، لا يوجد دليل قوي على تشفير/ضغط شامل",
                confidence=Confidence.MEDIUM, provenance=Provenance.INFERRED,
                source="crypto:entropy", method="shannon",
                data={"overall_entropy": overall}
            ))

        if high_windows > len(windows)*0.3 and len(windows) > 5:
            findings.append(Finding(
                id="crypto.packed_sections", category="crypto", title="نوافذ عالية الإنتروبي كثيرة",
                description=f"{high_windows}/{len(windows)} نوافذ بإنتروبي >7.5 — قد تشير لمقاطع مشفرة/مضغوطة",
                confidence=Confidence.MEDIUM, provenance=Provenance.INFERRED,
                source="crypto:window_entropy", method="1KB sliding window",
                data={"high_windows": high_windows, "total": len(windows)}
            ))

        if constants:
            findings.append(Finding(
                id="crypto.constants", category="crypto", title="ثوابت تشفير معروفة",
                description="تم العثور على ثوابت/علامات تشفير",
                confidence=Confidence.HIGH, provenance=Provenance.OBSERVED,
                source="crypto:constant search", method="byte pattern search",
                data={"constants": constants}
            ))
        else:
            findings.append(Finding(
                id="crypto.no_constants", category="crypto", title="لا توجد ثوابت تشفير واضحة",
                description="لم يتم العثور على S-box أو PEM markers أو base64 alphabet كامل",
                confidence=Confidence.MEDIUM, provenance=Provenance.OBSERVED,
                source="crypto:constant search", method="byte pattern search",
                data={}
            ))

        res.findings = findings
        res.raw = raw
        return res
