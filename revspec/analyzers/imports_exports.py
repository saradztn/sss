from __future__ import annotations
import re
from .base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding
from ..core.confidence import Confidence, Provenance
from ..core.context import AnalysisContext
from ..core.utils import run_cmd, which

class ImportsExportsAnalyzer(BaseAnalyzer):
    name = "imports_exports"
    description = "تحليل الاستيرادات والصادرات والاعتمادات"
    version = "1.0.0"

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        res = self._result_shell()
        p = ctx.sample_path
        raw = {}
        findings = []

        plat = ctx.shared.get("platform", {})
        fmt = plat.get("format","")

        imports = []
        exports = []
        needed_libs = []

        if fmt == "ELF":
            if which("readelf"):
                out = run_cmd(["readelf", "-d", str(p)])
                raw["readelf_d"] = out["stdout"]
                ctx.store.save_text(f"evidence/{self.name}/readelf_d.txt", out["stdout"])
                # NEEDED
                needed_libs = re.findall(r"NEEDED\s+.*\[(.+?)\]", out["stdout"])
                raw["needed"] = needed_libs
            if which("nm"):
                out = run_cmd(["nm", "-D", str(p)], timeout=10)
                raw["nm_D"] = out["stdout"][:10000]
                ctx.store.save_text(f"evidence/{self.name}/nm_D.txt", out["stdout"])
                # parse imports (U)
                for line in out["stdout"].splitlines():
                    if " U " in line:
                        parts = line.strip().split()
                        if parts:
                            imports.append(parts[-1])
                    elif " T " in line or " t " in line:
                        # defined
                        pass
                raw["imports_nm"] = imports[:500]
            if which("objdump"):
                out = run_cmd(["objdump", "-T", str(p)], timeout=10)
                raw["objdump_T"] = out["stdout"][:10000]
                ctx.store.save_text(f"evidence/{self.name}/objdump_T.txt", out["stdout"])
            # ldd?
            if which("ldd"):
                out = run_cmd(["ldd", str(p)], timeout=10)
                raw["ldd"] = out["stdout"][:5000]
                ctx.store.save_text(f"evidence/{self.name}/ldd.txt", out["stdout"])
        elif fmt == "PE":
            # try pefile
            try:
                import pefile
                pe = pefile.PE(str(p), fast_load=False)
                pe.parse_data_directories()
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll = entry.dll.decode(errors="ignore")
                        needed_libs.append(dll)
                        for imp in entry.imports:
                            name = imp.name.decode(errors="ignore") if imp.name else f"ordinal_{imp.ordinal}"
                            imports.append(f"{dll}!{name}")
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            exports.append(exp.name.decode(errors="ignore"))
                raw["pe_imports"] = imports[:1000]
                raw["pe_exports"] = exports[:1000]
                raw["pe_needed"] = needed_libs
            except Exception as e:
                raw["pefile_error"] = str(e)
                if which("objdump"):
                    out = run_cmd(["objdump", "-p", str(p)])
                    raw["objdump_p"] = out["stdout"][:10000]
                    # parse DLL Name
                    needed_libs = re.findall(r"DLL Name:\s*(\S+)", out["stdout"])
                    raw["needed"] = needed_libs
        else:
            # generic: try strings for imports-like?
            if which("strings"):
                pass

        # also try python import detection for scripts
        if fmt == "SCRIPT":
            text = p.read_text(errors="ignore")[:20000]
            # crude import detection
            py_imports = re.findall(r"^\s*import\s+(\S+)", text, re.M)
            py_imports += re.findall(r"^\s*from\s+(\S+)\s+import", text, re.M)
            imports.extend(py_imports)
            raw["script_imports"] = py_imports

        # save raw
        ctx.store.save_json(f"evidence/{self.name}/raw.json", {"imports": imports[:1000], "exports": exports[:1000], "needed": needed_libs, **{k:v for k,v in raw.items() if k not in ("imports","pe_imports")}})
        ctx.shared["imports"] = imports
        ctx.shared["needed_libs"] = needed_libs

        # findings
        if needed_libs:
            findings.append(Finding(
                id="deps.needed_libs", category="dependencies", title="المكتبات المطلوبة (NEEDED / DLL)",
                description=f"عدد {len(needed_libs)} مكتبة معتمدة",
                confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                source=f"{self.name}:readelf/pefile", method="readelf -d / pefile",
                data={"needed_libs": needed_libs}
            ))
        if imports:
            findings.append(Finding(
                id="deps.imports", category="dependencies", title="الرموز المستوردة",
                description=f"عدد {len(imports)} رمز مستورد (عينة 100 أولى محفوظة)",
                confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                source=f"{self.name}:nm/objdump/pefile", method="nm -D / objdump",
                data={"imports_sample": imports[:100], "total": len(imports)}
            ))
        if exports:
            findings.append(Finding(
                id="deps.exports", category="dependencies", title="الرموز المصدّرة",
                description=f"عدد {len(exports)} رمز مصدّر",
                confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                source=f"{self.name}:pefile/objdump", method="pefile / objdump",
                data={"exports": exports[:100]}
            ))
        if not needed_libs and not imports and not exports:
            findings.append(Finding(
                id="deps.none_found", category="dependencies", title="لا توجد اعتمادات ظاهرة أو تعذر الاستخراج",
                description="لم يتم العثور على imports/needed؛ قد يكون statically linked أو stripped أو يحتاج أدوات إضافية",
                confidence=Confidence.UNKNOWN, provenance=Provenance.UNDETERMINED,
                source=f"{self.name}:empty", method="no tool output",
                data=raw
            ))

        # Heuristic: suspicious imports
        suspicious = []
        susp_keywords = ["ptrace","inject","hook","mmap","mprotect","execve","system","popen","socket","connect","bind","listen","CreateRemoteThread","VirtualAlloc","WriteProcessMemory"]
        for imp in imports:
            for kw in susp_keywords:
                if kw.lower() in imp.lower():
                    suspicious.append(imp)
                    break
        if suspicious:
            findings.append(Finding(
                id="deps.suspicious_imports", category="behavior", title="استيرادات مثيرة للانتباه",
                description="استيرادات قد تشير لقدرات حساسة (لا تعني خبثًا بحد ذاتها)",
                confidence=Confidence.MEDIUM, provenance=Provenance.INFERRED,
                source=f"{self.name}:heuristic", method="keyword match against imports",
                data={"suspicious": suspicious[:50]}, tags=["heuristic","behavior"]
            ))

        res.findings = findings
        res.raw = {"needed": needed_libs, "imports_total": len(imports), "exports_total": len(exports)}
        return res
