from __future__ import annotations
import pathlib
import datetime
import hashlib
import mimetypes
import os
import stat

from .base import BaseAnalyzer
from ..core.types import AnalyzerResult, Finding, EvidenceRef
from ..core.confidence import Confidence, Provenance
from ..core.context import AnalysisContext
from ..core.utils import run_cmd, which

class MetadataAnalyzer(BaseAnalyzer):
    name = "metadata"
    description = "File metadata, hashes, file(1), timestamps"
    version = "1.0.0"

    def analyze(self, ctx: AnalysisContext) -> AnalyzerResult:
        res = self._result_shell()
        p = ctx.sample_path
        st = p.stat()
        findings = []

        # hashes already in ctx.sample but recompute to prove
        import hashlib
        def hash_file(algo):
            h = hashlib.new(algo)
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()

        sha256 = hash_file("sha256")
        sha1 = hash_file("sha1")
        md5 = hash_file("md5")
        size = st.st_size
        mtime = datetime.datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z"
        ctime = datetime.datetime.utcfromtimestamp(st.st_ctime).isoformat() + "Z"
        mode = oct(stat.S_IMODE(st.st_mode))

        # file command
        file_output = ""
        mime = None
        if which("file"):
            out = run_cmd(["file", "-b", str(p)])
            file_output = out["stdout"].strip()
            out2 = run_cmd(["file", "-b", "--mime-type", str(p)])
            mime = out2["stdout"].strip() or None
            # save raw
            ctx.store.save_text(f"evidence/{self.name}/file_output.txt", file_output + "\n" + (mime or ""))

        ctx.store.save_json(f"evidence/{self.name}/raw.json", {
            "size": size, "sha256": sha256, "sha1": sha1, "md5": md5,
            "mtime": mtime, "ctime": ctime, "mode": mode,
            "file_b": file_output, "mime": mime
        })

        findings.append(Finding(
            id="meta.hash.sha256", category="metadata", title="SHA256",
            description=f"SHA256 للعينة = {sha256}",
            confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
            source="metadata:hashlib.sha256", method="hashlib.sha256 over file bytes",
            data={"sha256": sha256}
        ))
        findings.append(Finding(
            id="meta.size", category="metadata", title="حجم الملف",
            description=f"حجم الملف {size} بايت",
            confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
            source="metadata:stat", method="stat.st_size",
            data={"size_bytes": size}
        ))
        findings.append(Finding(
            id="meta.timestamps", category="metadata", title="طوابع زمنية لنظام الملفات",
            description="mtime/ctime من نظام الملفات (قد لا تعكس وقت البناء)",
            confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
            source="metadata:stat", method="stat.st_mtime/ctime",
            data={"mtime": mtime, "ctime": ctime, "mode": mode}
        ))
        if file_output:
            findings.append(Finding(
                id="meta.file_magic", category="metadata", title="نوع الملف (file magic)",
                description=file_output,
                confidence=Confidence.HIGH, provenance=Provenance.OBSERVED,
                source="metadata:file(1)", method="file -b",
                data={"file_output": file_output, "mime": mime}
            ))
        # magic bytes
        with p.open("rb") as f:
            magic = f.read(16).hex()
        findings.append(Finding(
            id="meta.magic_bytes", category="metadata", title="Magic bytes",
            description=f"أول 16 بايت hex: {magic}",
            confidence=Confidence.PROVEN, provenance=Provenance.OBSERVED,
            source="metadata:read", method="read first 16 bytes",
            data={"magic_hex": magic}
        ))

        res.findings = findings
        res.raw = {"sha256": sha256, "size": size, "file": file_output, "mime": mime}
        res.status = "ok"
        return res
