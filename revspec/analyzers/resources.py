from __future__ import annotations
import re
import pathlib
from .base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding
from ..core.confidence import Confidence, Provenance
from ..core.context import AnalysisContext
from ..core.utils import run_cmd, which

class ResourcesAnalyzer(BaseAnalyzer):
    name = "resources"
    description = "استخراج الموارد، الإعدادات، والملفات المرافقة"
    version = "1.0.0"

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        res = self._result_shell()
        p = ctx.sample_path
        raw = {}
        findings = []

        # Check if file is archive (zip)
        is_zip = False
        with p.open("rb") as f:
            mag = f.read(4)
            if mag == b"PK\x03\x04":
                is_zip = True
        raw["is_zip"] = is_zip

        # strings already has paths, but we also look for config-like strings
        strings_raw = ctx.shared.get("strings_raw", {})
        urls = strings_raw.get("urls", [])
        paths_sample = strings_raw.get("paths_sample", [])

        # Look for config files / resources via strings
        config_hints = []
        for s in (strings_raw.get("paths_sample", []) or []):
            low = s.lower()
            if any(ext in low for ext in [".ini",".cfg",".conf",".json",".xml",".yaml",".yml",".toml",".properties",".db",".sqlite"]):
                config_hints.append(s)
        raw["config_hints"] = config_hints[:100]

        # If ELF/PE, use objdump to list resources? For PE try wrestool/rcedit if available
        embedded = []
        if is_zip:
            if which("unzip"):
                out = run_cmd(["unzip", "-l", str(p)])
                raw["zip_list"] = out["stdout"][:5000]
                ctx.store.save_text(f"evidence/{self.name}/zip_list.txt", out["stdout"])
                # count files
                lines = out["stdout"].splitlines()
                findings.append(Finding(
                    id="res.zip.contents", category="resources", title="موارد داخل حاوية ZIP/JAR/APK",
                    description=f"{len(lines)} سطر من unzip -l",
                    confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                    source="resources:unzip", method="unzip -l",
                    data={"zip_list_preview": out["stdout"][:2000]}
                ))
            # try to list with python zipfile
            try:
                import zipfile
                with zipfile.ZipFile(p) as z:
                    names = z.namelist()
                    raw["zip_namelist"] = names[:500]
                    embedded.extend(names[:500])
                    # save central directory
                    ctx.store.save_json(f"evidence/{self.name}/zip_namelist.json", {"files": names})
            except Exception as e:
                raw["zip_error"] = str(e)
        else:
            # look for embedded strings that look like resources
            # e.g., manifest, version info
            if which("strings"):
                # search for version strings
                out = run_cmd(["strings", str(p)], timeout=10)
                txt = out["stdout"]
                # find version patterns
                vers = re.findall(r"\b\d+\.\d+\.\d+(?:\.\d+)?\b", txt)
                raw["version_strings"] = list(set(vers))[:20]
                if vers:
                    findings.append(Finding(
                        id="res.version_strings", category="resources", title="سلاسل إصدار",
                        description="سلاسل تشبه أرقام إصدار",
                        confidence=Confidence.MEDIUM, provenance=Provenance.INFERRED,
                        source="resources:regex", method="version regex",
                        data={"versions": list(set(vers))[:20]}
                    ))

        # Check for .rodata / .rdata via readelf/objdump
        if which("readelf"):
            out = run_cmd(["readelf", "-S", str(p)])
            # find .rodata size
            m = re.search(r"\.rodata\s+\w+\s+(\S+)\s+(\S+)\s+(\S+)", out["stdout"])
            if m:
                raw["rodata"] = m.group(0).strip()
        if which("objdump") and not is_zip:
            out = run_cmd(["objdump", "-s", "-j", ".rodata", str(p)], timeout=10)
            if out["returncode"] == 0 and out["stdout"]:
                # save snippet
                ctx.store.save_text(f"evidence/{self.name}/rodata_hex.txt", out["stdout"][:5000])
                raw["rodata_hex_snippet"] = out["stdout"][:1000]

        # Generic: entropy or strings indicating packing
        # We'll leave crypto density to crypto analyzer

        ctx.store.save_json(f"evidence/{self.name}/raw.json", raw)

        # Findings
        if config_hints:
            findings.append(Finding(
                id="res.config_hints", category="resources", title="تلميحات ملفات إعداد",
                description="مسارات تشبه ملفات إعداد/قواعد بيانات",
                confidence=Confidence.MEDIUM, provenance=Provenance.INFERRED,
                source="resources:strings regex", method="extension keyword",
                data={"configs": config_hints[:50]}
            ))
        if embedded:
            findings.append(Finding(
                id="res.embedded_list", category="resources", title="موارد مضمنة",
                description=f"{len(embedded)} مورد مضمن (من ZIP)",
                confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                source="resources:zipfile", method="zipfile.namelist",
                data={"embedded_sample": embedded[:50]}
            ))
        if not findings:
            findings.append(Finding(
                id="res.no_obvious", category="resources", title="لا توجد موارد ظاهرة بالطرق المتاحة",
                description="لم يتم العثور على موارد مضمنة واضحة؛ قد تكون مضمنة كـ blobs أو مشفرة",
                confidence=Confidence.UNKNOWN, provenance=Provenance.UNDETERMINED,
                source="resources:negation", method="no zip / no version",
                data=raw
            ))

        res.findings = findings
        res.raw = raw
        return res
