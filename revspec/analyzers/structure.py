from __future__ import annotations
import re
from .base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding
from ..core.confidence import Confidence, Provenance
from ..core.context import AnalysisContext
from ..core.utils import run_cmd, which


class StructureAnalyzer(BaseAnalyzer):
    name = "structure"
    description = "تحليل البنية الداخلية: sections, segments, entry point"
    version = "1.0.0"

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        res = self._result_shell()
        p = ctx.sample_path
        raw = {}
        findings = []

        plat = ctx.shared.get("platform", {})
        fmt = plat.get("format", "unknown")

        if fmt == "ELF":
            if which("readelf"):
                for flag, label in [("-S", "sections"), ("-l", "segments"), ("-h", "header"), ("-d", "dynamic")]:
                    out = run_cmd(["readelf", flag, str(p)])
                    raw[label] = out["stdout"]
                    ctx.store.save_text(f"evidence/{self.name}/readelf_{label}.txt", out["stdout"])
                # parse entry point
                m = re.search(r"Entry point address:\s*(\S+)", raw.get("header",""))
                if m:
                    raw["entry_point"] = m.group(1)
                # parse sections count
                sec_count = raw.get("sections","").count("PROGBITS") + raw.get("sections","").count("STRTAB")
                # findings
                findings.append(Finding(
                    id="struct.elf.header", category="structure", title="ELF header",
                    description=f"Entry: {raw.get('entry_point','unknown')} | OSABI: {plat.get('osabi','')}",
                    confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                    source="structure:readelf -h", method="readelf -h",
                    data={"entry_point": raw.get("entry_point"), "header": raw.get("header","")[:2000]}
                ))
                # sections
                findings.append(Finding(
                    id="struct.elf.sections", category="structure", title="Sections / Segments",
                    description="قائمة sections و segments كما أظهرها readelf",
                    confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                    source="structure:readelf -S/-l", method="readelf",
                    data={"sections_raw": raw.get("sections","")[:4000], "segments_raw": raw.get("segments","")[:4000]}
                ))
            else:
                findings.append(Finding(
                    id="struct.no_tool", category="structure", title="تعذر تحليل البنية لعدم وجود readelf",
                    description="readelf غير متوفر، لا يمكن استخراج البنية بالتفصيل",
                    confidence=Confidence.UNKNOWN, provenance=Provenance.UNDETERMINED,
                    source="structure:missing", method="which readelf",
                    data={}
                ))
        elif fmt == "PE":
            # try objdump or pefile if available
            tried = False
            try:
                import pefile  # type: ignore
                pe = pefile.PE(str(p), fast_load=False)
                raw["pe_sections"] = [{"Name": s.Name.decode(errors="ignore").strip("\x00"), "VirtualAddress": hex(s.VirtualAddress), "Misc_VirtualSize": s.Misc_VirtualSize, "SizeOfRawData": s.SizeOfRawData} for s in pe.sections]
                raw["pe_entry"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                raw["pe_image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
                ctx.store.save_json(f"evidence/{self.name}/pe.json", raw)
                findings.append(Finding(
                    id="struct.pe.sections", category="structure", title="PE Sections",
                    description=f"PE entry {raw['pe_entry']} base {raw['pe_image_base']} sections={len(raw['pe_sections'])}",
                    confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                    source="structure:pefile", method="pefile.PE",
                    data=raw
                ))
                tried = True
            except Exception as e:
                raw["pefile_error"] = str(e)
            if not tried and which("objdump"):
                out = run_cmd(["objdump", "-h", str(p)])
                raw["objdump_h"] = out["stdout"]
                ctx.store.save_text(f"evidence/{self.name}/objdump_h.txt", out["stdout"])
                findings.append(Finding(
                    id="struct.pe.objdump", category="structure", title="PE structure via objdump",
                    description="Sections كما أظهرها objdump -h",
                    confidence=Confidence.HIGH, provenance=Provenance.OBSERVED,
                    source="structure:objdump", method="objdump -h",
                    data={"objdump_h": out["stdout"][:4000]}
                ))
        elif fmt in ("Mach-O", "Mach-O FAT"):
            if which("objdump"):
                out = run_cmd(["objdump", "-h", str(p)])
                raw["objdump_h"] = out["stdout"]
                ctx.store.save_text(f"evidence/{self.name}/objdump_h.txt", out["stdout"])
                findings.append(Finding(
                    id="struct.macho.sections", category="structure", title="Mach-O sections",
                    description=out["stdout"][:1000],
                    confidence=Confidence.HIGH, provenance=Provenance.OBSERVED,
                    source="structure:objdump", method="objdump -h",
                    data={}
                ))
        elif fmt == "SCRIPT":
            # structure is file content
            text = p.read_text(errors="ignore")[:5000]
            raw["preview"] = text[:2000]
            findings.append(Finding(
                id="struct.script.preview", category="structure", title="Script structure",
                description=f"أول 2000 حرف من السكربت، {len(text)} حرف إجمالي",
                confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                source="structure:read", method="read_text",
                data={"preview": text[:2000]}
            ))
        else:
            # generic: try to detect ZIP containers
            if which("unzip"):
                out = run_cmd(["unzip", "-l", str(p)], timeout=10)
                if out["returncode"] == 0:
                    raw["zip_list"] = out["stdout"][:5000]
                    ctx.store.save_text(f"evidence/{self.name}/zip_list.txt", out["stdout"])
                    findings.append(Finding(
                        id="struct.zip.contents", category="structure", title="ZIP container contents",
                        description="محتويات الحاوية ZIP كما أظهرها unzip -l",
                        confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
                        source="structure:unzip", method="unzip -l",
                        data={"zip_list": out["stdout"][:3000]}
                    ))
            if not findings:
                findings.append(Finding(
                    id="struct.generic.unknown", category="structure", title="بنية غير محددة",
                    description="لم يكن هناك محلل بنية متخصص لهذا النوع؛ تم حفظ file output فقط",
                    confidence=Confidence.UNKNOWN, provenance=Provenance.UNDETERMINED,
                    source="structure:fallback", method="none",
                    data=raw
                ))

        # store raw
        ctx.store.save_json(f"evidence/{self.name}/raw.json", raw)
        ctx.shared["structure_raw"] = raw
        res.findings = findings
        res.raw = raw
        return res
