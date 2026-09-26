from __future__ import annotations
import re
from .base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding
from ..core.confidence import Confidence, Provenance
from ..core.context import AnalysisContext
from ..core.utils import run_cmd, which

# Suspicious API mapping
BEHAVIOR_RULES = [
    (r"\b(socket|connect|bind|listen|accept|send|recv)\b", "network", "عمليات شبكة"),
    (r"\b(open|read|write|fopen|fwrite|fread|creat)\b", "file-io", "عمليات ملفات"),
    (r"\b(execve|execvp|system|popen|fork|clone)\b", "process", "إنشاء عمليات"),
    (r"\b(mmap|mprotect|VirtualAlloc|VirtualProtect)\b", "memory", "تلاعب بالذاكرة / حقن محتمل"),
    (r"\b(ptrace|CreateRemoteThread|WriteProcessMemory)\b", "injection", "حقن/تتبع عمليات"),
    (r"\b(crypt|encrypt|decrypt|AES|RSA|EVP_)\b", "crypto", "عمليات تشفير"),
    (r"\b(getenv|setenv|getuid|setuid)\b", "env", "تفاعل مع البيئة/الصلاحيات"),
]

class BehaviorAnalyzer(BaseAnalyzer):
    name = "behavior"
    description = "تحليل سلوكي ثابت عبر الـimports والسلاسل"
    version = "1.0.0"

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        res = self._result_shell()
        imports = ctx.shared.get("imports", [])
        strings_raw = ctx.shared.get("strings_raw", {})
        raw = {}
        findings = []

        # Combine imports + strings for behavior search
        corpus = "\n".join(imports) + "\n" + "\n".join(strings_raw.get("urls", [])) + "\n" + " ".join(strings_raw.get("keywords", {}).keys() if isinstance(strings_raw.get("keywords"), dict) else [])

        # Also get strings ascii content if needed
        strings_text = ""
        p = ctx.store.run_dir / f"evidence/strings/strings_ascii.txt"
        if p.exists():
            strings_text = p.read_text(errors="ignore")[:200000]
            corpus = corpus + "\n" + strings_text

        detected_behaviors = []
        for pattern, tag, desc in BEHAVIOR_RULES:
            hits = re.findall(pattern, corpus, flags=re.I)
            if hits:
                uniq = list(set(hits))[:20]
                detected_behaviors.append({"tag": tag, "description": desc, "hits": uniq, "pattern": pattern})
                raw[tag] = uniq

        ctx.store.save_json(f"evidence/{self.name}/raw.json", {"detected": detected_behaviors, "raw": raw})

        if detected_behaviors:
            for beh in detected_behaviors:
                findings.append(Finding(
                    id=f"behavior.{beh['tag']}", category="behavior", title=f"سلوك محتمل: {beh['description']}",
                    description=f"تم العثور على {beh['hits']} مطابقة للنمط {beh['pattern']}",
                    confidence=Confidence.MEDIUM, provenance=Provenance.INFERRED,
                    source="behavior:regex over imports+strings", method=f"regex {beh['pattern']}",
                    data=beh, tags=[beh["tag"], "heuristic"]
                ))
        else:
            findings.append(Finding(
                id="behavior.none", category="behavior", title="لا يوجد سلوك مشبوه واضح بالتحليل الثابت",
                description="لم تطابق أي من قواعد السلوك",
                confidence=Confidence.MEDIUM, provenance=Provenance.OBSERVED,
                source="behavior:negation", method="regex rules returned empty",
                data={}
            ))

        # Also document observable I/O from strings: CLI hints
        cli_hints = []
        if strings_text:
            for line in strings_text.splitlines():
                if line.startswith("-") and len(line) < 30:
                    cli_hints.append(line)
                if "--" in line and len(line) < 50:
                    cli_hints.append(line)
        # filter
        cli_hints = list(dict.fromkeys([h.strip() for h in cli_hints if 2 <= len(h.strip()) <= 30]))[:50]
        if cli_hints:
            raw["cli_hints"] = cli_hints
            findings.append(Finding(
                id="behavior.cli_hints", category="interfaces", title="تلميحات واجهة سطر الأوامر",
                description="سلاسل تشبه خيارات CLI",
                confidence=Confidence.LOW, provenance=Provenance.INFERRED,
                source="behavior:strings scan", method="lines starting with -",
                data={"cli_hints": cli_hints}, tags=["interface"]
            ))

        res.findings = findings
        res.raw = raw
        return res
