from __future__ import annotations
import re
from .base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding
from ..core.confidence import Confidence, Provenance
from ..core.context import AnalysisContext
from ..core.utils import run_cmd, which

class DisasmAnalyzer(BaseAnalyzer):
    name = "disasm"
    description = "Disassembly / Decompilation عندما يكون ممكنًا"
    version = "1.0.0"

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        res = self._result_shell()
        p = ctx.sample_path
        raw = {}
        findings = []

        plat = ctx.shared.get("platform", {})
        fmt = plat.get("format","")

        # Try capstone if available
        capstone_available = False
        try:
            import capstone  # type: ignore
            capstone_available = True
        except Exception:
            pass

        # Try objdump as primary
        disasm_output = ""
        if which("objdump"):
            # only for ELF/PE/MachO, attempt to disassemble .text
            out = run_cmd(["objdump", "-d", "-M", "intel", str(p)], timeout=20)
            disasm_output = out["stdout"]
            raw["objdump_returncode"] = out["returncode"]
            raw["objdump_lines"] = len(disasm_output.splitlines())
            raw["objdump_stderr_preview"] = out["stderr"][:500]
            # save truncated
            ctx.store.save_text(f"evidence/{self.name}/objdump_d.txt", disasm_output[:200000])  # cap 200k

            if out["returncode"] == 0 and len(disasm_output.splitlines()) > 10:
                # parse some stats
                # count functions (heuristic: lines with "<...>:")
                funcs = re.findall(r"<([^>]+)>:", disasm_output)
                uniq_funcs = list(dict.fromkeys(funcs))  # preserve order unique
                raw["functions_found"] = uniq_funcs[:200]
                raw["functions_count"] = len(uniq_funcs)

                # check for interesting instructions
                interesting = []
                if "syscall" in disasm_output:
                    interesting.append("syscall")
                if "int 0x80" in disasm_output:
                    interesting.append("int 0x80")
                raw["interesting_mnemonics"] = interesting

                findings.append(Finding(
                    id="disasm.objdump_ok", category="disasm", title="Disassembly عبر objdump",
                    description=f"تم تفكيك {len(disasm_output.splitlines())} سطر، {len(uniq_funcs)} دالة محتملة",
                    confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                    source="disasm:objdump -d", method="objdump -d -M intel",
                    data={"lines": len(disasm_output.splitlines()), "funcs": uniq_funcs[:50], "total_funcs": len(uniq_funcs)}
                ))
                # capstone check
                if capstone_available:
                    findings.append(Finding(
                        id="disasm.capstone_available", category="disasm", title="Capstone متاح",
                        description="يمكن استخدام capstone للتحليل البرمجي لاحقًا",
                        confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                        source="disasm:capstone import", method="import capstone",
                        data={}
                    ))
            else:
                findings.append(Finding(
                    id="disasm.objdump_failed", category="disasm", title="فشل Disassembly عبر objdump",
                    description=out["stderr"][:500] or "لا يوجد خرج",
                    confidence=Confidence.MEDIUM, provenance=Provenance.OBSERVED,
                    source="disasm:objdump", method="objdump -d",
                    data={"returncode": out["returncode"], "stderr": out["stderr"][:500]}
                ))
        else:
            findings.append(Finding(
                id="disasm.no_tool", category="disasm", title="لا توجد أدوات تفكيك",
                description="objdump غير متوفر ولا يمكن التفكيك",
                confidence=Confidence.UNKNOWN, provenance=Provenance.UNDETERMINED,
                source="disasm:missing", method="which objdump",
                data={}
            ))

        # Try to detect if stripped
        if which("file"):
            out = run_cmd(["file", str(p)])
            if "stripped" in out["stdout"]:
                raw["stripped"] = True
                findings.append(Finding(
                    id="disasm.stripped", category="disasm", title="الملف stripped",
                    description="الرموز (symbols) مجردة — يصعّب إعادة البناء الحرفي",
                    confidence=Confidence.HIGH, provenance=Provenance.OBSERVED,
                    source="disasm:file", method="file output contains 'stripped'",
                    data={"file_output": out["stdout"].strip()}
                ))
            elif "not stripped" in out["stdout"]:
                raw["stripped"] = False
                findings.append(Finding(
                    id="disasm.not_stripped", category="disasm", title="الملف not stripped",
                    description="الرموز موجودة — يساعد في إعادة البناء",
                    confidence=Confidence.HIGH, provenance=Provenance.OBSERVED,
                    source="disasm:file", method="file output",
                    data={"file_output": out["stdout"].strip()}
                ))

        # Decompilation note: we do NOT claim to recover original source
        findings.append(Finding(
            id="disasm.decompilation_limitation", category="disasm", title="قيود الاستعادة",
            description="لا يمكن استعادة المصدر الأصلي حرفيًا من binary؛ ما نستعيده هو سلوك مكافئ عبر الملاحظة والتفكيك. Decompilation الحقيقي يتطلب Ghidra/IDA غير مضمنة هنا.",
            confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
            source="disasm:disclaimer", method="design principle",
            data={}
        ))

        ctx.store.save_json(f"evidence/{self.name}/raw.json", raw)
        res.findings = findings
        res.raw = raw
        return res
