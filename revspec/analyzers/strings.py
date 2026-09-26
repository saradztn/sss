from __future__ import annotations
import re
from pathlib import Path
from .base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding
from ..core.confidence import Confidence, Provenance
from ..core.context import AnalysisContext
from ..core.utils import run_cmd, which

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PATH_RE = re.compile(r"(?:/[\w\-.]+)+")
REG_RE = re.compile(r"HKEY_[A-Z_]+\\[^\s]+", re.I)

class StringsAnalyzer(BaseAnalyzer):
    name = "strings"
    description = "استخراج وتحليل السلاسل النصية"
    version = "1.0.0"

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        res = self._result_shell()
        p = ctx.sample_path
        raw = {}
        findings = []

        # use strings(1) if available else python fallback
        strings_out = ""
        if which("strings"):
            # -a scan whole file, -n 4 min length
            out = run_cmd(["strings", "-a", "-n", "4", str(p)], timeout=15)
            strings_out = out["stdout"]
            # also utf16?
            out16 = run_cmd(["strings", "-a", "-n", "4", "-e", "l", str(p)], timeout=15)
            strings_utf16 = out16["stdout"]
            raw["strings_ascii_lines"] = len(strings_out.splitlines())
            raw["strings_utf16_lines"] = len(strings_utf16.splitlines())
            combined = strings_out + "\n" + strings_utf16
            ctx.store.save_text(f"evidence/{self.name}/strings_ascii.txt", strings_out)
            ctx.store.save_text(f"evidence/{self.name}/strings_utf16.txt", strings_utf16)
        else:
            # python fallback: extract ascii
            data = p.read_bytes()
            cur = []
            out_lines = []
            for b in data:
                if 32 <= b <= 126:
                    cur.append(chr(b))
                else:
                    if len(cur) >= 4:
                        out_lines.append("".join(cur))
                    cur = []
            strings_out = "\n".join(out_lines)
            combined = strings_out
            raw["fallback"] = True
            raw["strings_ascii_lines"] = len(out_lines)
            ctx.store.save_text(f"evidence/{self.name}/strings_ascii.txt", strings_out)

        # analysis
        combined = strings_out  # for initial simple
        # also include utf16 if present
        if "strings_utf16" not in locals():
            strings_utf16 = ""
        else:
            combined = strings_out + "\n" + strings_utf16

        urls = list(set(URL_RE.findall(combined)))[:100]
        ips = list(set(IP_RE.findall(combined)))[:100]
        emails = list(set(EMAIL_RE.findall(combined)))[:100]
        paths = list(set(PATH_RE.findall(combined)))[:100]
        regs = list(set(REG_RE.findall(combined)))[:100]

        # interesting keywords
        keywords = {}
        interesting = ["password","passwd","secret","api_key","apikey","token","config","database","db_","sql","http","debug","error","fail","success","admin","root","key","encrypt","decrypt","auth","login","user","credential","AES","RSA","DES","base64","BEGIN CERTIFICATE","BEGIN PRIVATE","BEGIN PUBLIC"]
        lower = combined.lower()
        for kw in interesting:
            if kw.lower() in lower:
                # count occurrences
                cnt = lower.count(kw.lower())
                keywords[kw] = cnt

        raw.update({
            "urls": urls,
            "ips": ips,
            "emails": emails,
            "paths_sample": paths[:50],
            "regs": regs,
            "keywords": keywords,
            "total_strings": len(combined.splitlines())
        })
        ctx.store.save_json(f"evidence/{self.name}/analysis.json", raw)
        ctx.shared["strings_raw"] = raw

        # findings
        findings.append(Finding(
            id="strings.summary", category="strings", title="ملخص السلاسل",
            description=f"إجمالي {raw['strings_ascii_lines']} سلسلة ascii (+ {raw.get('strings_utf16_lines',0)} utf16)",
            confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
            source="strings:strings(1)", method="strings -a -n 4",
            data={"ascii": raw["strings_ascii_lines"], "utf16": raw.get("strings_utf16_lines",0)}
        ))
        if urls:
            findings.append(Finding(
                id="strings.urls", category="strings", title="URLs مكتشفة",
                description="عناوين URL مستخرجة من السلاسل",
                confidence=Confidence.HIGH, provenance=Provenance.OBSERVED,
                source="strings:regex", method="regex https?://",
                data={"urls": urls},
                tags=["network","ioc"]
            ))
        if ips:
            findings.append(Finding(
                id="strings.ips", category="strings", title="عناوين IP",
                description="عناوين IP محتملة",
                confidence=Confidence.MEDIUM, provenance=Provenance.INFERRED,
                source="strings:regex", method="ipv4 regex",
                data={"ips": ips}, tags=["network"]
            ))
        if emails:
            findings.append(Finding(
                id="strings.emails", category="strings", title="عناوين بريد",
                description="عناوين بريد مستخرجة",
                confidence=Confidence.HIGH, provenance=Provenance.OBSERVED,
                source="strings:regex", method="email regex",
                data={"emails": emails}
            ))
        if keywords:
            findings.append(Finding(
                id="strings.keywords", category="strings", title="كلمات مفتاحية مثيرة",
                description="كلمات دلالية قد تشير لوظائف حساسة",
                confidence=Confidence.MEDIUM, provenance=Provenance.INFERRED,
                source="strings:keyword search", method="case-insensitive substring count",
                data={"keywords": keywords}, tags=["heuristic"]
            ))
        if paths:
            findings.append(Finding(
                id="strings.paths", category="strings", title="مسارات ملفات",
                description="مسارات ملفات مستخرجة (عينة من 50)",
                confidence=Confidence.MEDIUM, provenance=Provenance.INFERRED,
                source="strings:regex", method="path regex",
                data={"paths": paths[:50]}
            ))
        if not urls and not ips and not keywords:
            findings.append(Finding(
                id="strings.no_ioc", category="strings", title="لا يوجد IOC واضح",
                description="لم يتم العثور على URLs/IPs/كلمات حساسة واضحة",
                confidence=Confidence.MEDIUM, provenance=Provenance.OBSERVED,
                source="strings:negation", method="empty regex results",
                data={}
            ))

        res.findings = findings
        res.raw = raw
        return res
