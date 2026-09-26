from __future__ import annotations
import pathlib
import re
import struct

from .base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding, EvidenceRef
from ..core.confidence import Confidence, Provenance
from ..core.context import AnalysisContext
from ..core.utils import run_cmd, which

# Lightweight ELF/PE/MachO detection without external deps
ELF_MAGIC = b"\x7fELF"

def detect_elf(path: pathlib.Path):
    with path.open("rb") as f:
        hdr = f.read(64)
        if not hdr.startswith(ELF_MAGIC):
            return None
        ei_class = hdr[4]
        ei_data = hdr[5]
        ei_version = hdr[6]
        ei_osabi = hdr[7]
        bitness = 32 if ei_class == 1 else 64 if ei_class == 2 else None
        endian = "little" if ei_data == 1 else "big" if ei_data == 2 else "unknown"
        # e_machine at offset 18 (2 bytes)
        e_machine = struct.unpack("<H" if endian=="little" else ">H", hdr[18:20])[0] if len(hdr)>=20 else None
        e_type = struct.unpack("<H" if endian=="little" else ">H", hdr[16:18])[0] if len(hdr)>=18 else None
        machines = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 8: "MIPS"}
        arch = machines.get(e_machine, f"e_machine={e_machine}")
        etypes = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
        ftype = etypes.get(e_type, str(e_type))
        osabi_map = {0: "SystemV", 3: "Linux", 6: "Solaris", 9: "FreeBSD", 12: "OpenBSD"}
        osabi = osabi_map.get(ei_osabi, str(ei_osabi))
        return {
            "format": "ELF",
            "bitness": bitness,
            "endian": endian,
            "arch": arch,
            "e_machine": e_machine,
            "e_type": ftype,
            "osabi": osabi,
            "ei_osabi_raw": ei_osabi,
        }

def detect_pe(path: pathlib.Path):
    with path.open("rb") as f:
        hdr = f.read(2)
        if hdr != b"MZ":
            return None
        f.seek(0x3C)
        e_lfanew_bytes = f.read(4)
        if len(e_lfanew_bytes) < 4:
            return None
        e_lfanew = struct.unpack("<I", e_lfanew_bytes)[0]
        f.seek(e_lfanew)
        sig = f.read(4)
        if sig != b"PE\x00\x00":
            return None
        machine_bytes = f.read(2)
        machine = struct.unpack("<H", machine_bytes)[0] if len(machine_bytes)==2 else None
        machines = {0x14c: "x86", 0x8664: "x86-64", 0x1c0: "ARM", 0xaa64: "AArch64"}
        arch = machines.get(machine, f"machine={hex(machine) if machine else 'unknown'}")
        return {"format": "PE", "arch": arch, "machine": machine}

def detect_macho(path: pathlib.Path):
    with path.open("rb") as f:
        magic = f.read(4)
        magics = {
            b"\xfe\xed\xfa\xce": ("Mach-O", 32, "big"),
            b"\xce\xfa\xed\xfe": ("Mach-O", 32, "little"),
            b"\xfe\xed\xfa\xcf": ("Mach-O", 64, "big"),
            b"\xcf\xfa\xed\xfe": ("Mach-O", 64, "little"),
            b"\xca\xfe\xba\xbe": ("Mach-O FAT", None, "big"),
            b"\xbe\xba\xfe\xca": ("Mach-O FAT", None, "little"),
        }
        if magic in magics:
            fmt, bits, endian = magics[magic]
            return {"format": fmt, "bitness": bits, "endian": endian}
        return None

def detect_script(path: pathlib.Path):
    try:
        with path.open("rb") as f:
            first = f.read(1024)
            if first.startswith(b"#!"):
                line = first.splitlines()[0].decode(errors="ignore")
                return {"format": "SCRIPT", "shebang": line}
            # Check for Python bytecode, Java class, etc.
            if first.startswith(b"\xca\xfe\xba\xbe") or first.startswith(b"\xbe\xba\xfe\xca"):
                return {"format": "Mach-O FAT"}
            if first[:4] == b"\x50\x4b\x03\x04":
                return {"format": "ZIP/JAR/APK", "hint": "PK zip container"}
            if first[:2] == b"PK":
                return {"format": "ZIP-based"}
            text = first.decode(errors="ignore")
            if "<?xml" in text[:200]:
                return {"format": "XML"}
            if text.lstrip().startswith("{") or text.lstrip().startswith("["):
                # maybe json
                pass
    except Exception:
        pass
    return None


class PlatformAnalyzer(BaseAnalyzer):
    name = "platform"
    description = "تحديد المنصة والمعمارية والـruntime"
    version = "1.0.0"

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        res = self._result_shell()
        p = ctx.sample_path
        findings = []
        raw = {}

        # Try detectors in order
        detected = None
        method = ""
        for func, label in [(detect_elf, "elf_magic"), (detect_pe, "pe_magic"), (detect_macho, "macho_magic"), (detect_script, "shebang/zip")]:
            d = func(p)
            if d:
                detected = d
                method = label
                raw.update(d)
                raw["detector"] = label
                break
        if not detected:
            # fallback to file command
            if which("file"):
                out = run_cmd(["file", "-b", str(p)])
                raw["file_fallback"] = out["stdout"].strip()
                detected = {"format": "unknown", "file_output": raw["file_fallback"]}
                method = "file(1) fallback"
            else:
                detected = {"format": "unknown"}
                method = "no detector"

        ctx.store.save_json(f"evidence/{self.name}/raw.json", raw)
        # Also store readelf if ELF
        extra_logs = {}
        if detected.get("format") == "ELF":
            if which("readelf"):
                out = run_cmd(["readelf", "-h", str(p)])
                extra_logs["readelf_h"] = out["stdout"]
                ctx.store.save_text(f"evidence/{self.name}/readelf_h.txt", out["stdout"])
            if which("file"):
                out = run_cmd(["file", "-b", str(p)])
                extra_logs["file"] = out["stdout"]

        # Runtime / language heuristics via strings + file output
        hints = []
        # check interpreter
        if detected.get("format") == "ELF" and which("readelf"):
            out = run_cmd(["readelf", "-l", str(p)])
            m = re.search(r"interpreter:\s*(\S+)", out["stdout"])
            if m:
                hints.append(f"interpreter:{m.group(1)}")
                raw["interpreter"] = m.group(1)
            if "python" in out["stdout"].lower():
                hints.append("python")
        # strings hints
        if which("strings"):
            out = run_cmd(["strings", str(p)], timeout=10)
            s = out["stdout"].lower()
            for kw, lang in [("python", "Python"), (".py", "Python"), ("jvm", "JVM"), ("java", "Java"), ("node", "Node.js"), (".net", ".NET"), ("mscorlib", ".NET"), ("golang", "Go"), ("go.buildinfo", "Go"), ("rust", "Rust"), ("cpython", "Python")]:
                if kw in s:
                    hints.append(lang)
            raw["strings_hints"] = list(set(hints))

        # Build findings
        fmt = detected.get("format", "unknown")
        arch = detected.get("arch") or detected.get("machine") or "unknown"
        bitness = detected.get("bitness") or "unknown"
        confidence = Confidence.PROVEN if fmt in ("ELF","PE","Mach-O","Mach-O FAT") else Confidence.MEDIUM if fmt=="SCRIPT" else Confidence.LOW
        findings.append(Finding(
            id="platform.format", category="platform", title="صيغة الملف / المنصة",
            description=f"الصيغة المكتشفة: {fmt} | المعمارية: {arch} | البت: {bitness}",
            confidence=confidence, provenance=Provenance.OBSERVED if confidence==Confidence.PROVEN else Provenance.INFERRED,
            source=f"platform:{method}", method=method,
            data=detected
        ))
        if hints:
            findings.append(Finding(
                id="platform.runtime_hints", category="platform", title="تلميحات Runtime / اللغة",
                description="تلميحات لغوية/تقنية مستنتجة من strings و readelf",
                confidence=Confidence.LOW, provenance=Provenance.INFERRED,
                source="platform:strings+readelf", method="keyword search in strings",
                data={"hints": list(set(hints))}, tags=["heuristic"]
            ))
        else:
            findings.append(Finding(
                id="platform.runtime_unknown", category="platform", title="Runtime غير محدد",
                description="لم يتم العثور على تلميحات runtime واضحة",
                confidence=Confidence.UNKNOWN, provenance=Provenance.UNDETERMINED,
                source="platform:heuristics", method="keyword search returned empty",
                data={}
            ))

        # Store shared for later analyzers
        ctx.shared["platform"] = detected
        res.findings = findings
        res.raw = raw
        res.status = "ok"
        return res
