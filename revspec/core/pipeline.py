from __future__ import annotations
import datetime
import pathlib
import time
from typing import List, Dict, Any

from .types import PipelineResult, SampleInfo, HostInfo, sha256_file, sha1_file, md5_file
from .evidence import EvidenceStore
from .context import AnalysisContext
from .utils import tool_version, which
from ..analyzers.base import BaseAnalyzer

# Registry of analyzers in execution order
def default_analyzers(include_deep: bool = False) -> List[BaseAnalyzer]:
    # Import lazily to avoid circular
    from ..analyzers.metadata import MetadataAnalyzer
    from ..analyzers.platform import PlatformAnalyzer
    from ..analyzers.structure import StructureAnalyzer
    from ..analyzers.strings import StringsAnalyzer
    from ..analyzers.imports_exports import ImportsExportsAnalyzer
    from ..analyzers.resources import ResourcesAnalyzer
    from ..analyzers.crypto import CryptoAnalyzer
    from ..analyzers.disasm import DisasmAnalyzer
    from ..analyzers.behavior import BehaviorAnalyzer
    from ..analyzers.serial_spoof import SerialSpoofAnalyzer
    from ..dynamic.tracer import DynamicAnalyzer
    from ..compare.comparator import ComparatorAnalyzer
    analyzers = [
        MetadataAnalyzer(),
        PlatformAnalyzer(),
        StructureAnalyzer(),
        StringsAnalyzer(),
        ImportsExportsAnalyzer(),
        ResourcesAnalyzer(),
        CryptoAnalyzer(),
        DisasmAnalyzer(),
        BehaviorAnalyzer(),
        SerialSpoofAnalyzer(),
        DynamicAnalyzer(),
        ComparatorAnalyzer(),
    ]
    if include_deep:
        try:
            from ..deep.opcode_analyzer import DeepOpcodeAnalyzer
            analyzers.append(DeepOpcodeAnalyzer())
        except Exception as e:
            pass
    return analyzers

def collect_tool_versions() -> Dict[str,str]:
    tools = ["file","readelf","objdump","nm","strings","ldd","unzip","strace","bwrap","firejail","capstone"]
    versions = {}
    for t in tools:
        if which(t):
            try:
                versions[t] = tool_version(t)
            except Exception:
                versions[t] = "present"
        # else not present, skip
    # python packages
    try:
        import importlib.metadata as im
        for pkg in ["jinja2","yaml","jsonschema","pefile","lief","capstone","elftools"]:
            try:
                versions[pkg] = im.version(pkg)
            except Exception:
                pass
    except Exception:
        pass
    return versions

class Pipeline:
    def __init__(self, analyzers: List[BaseAnalyzer] = None, include_deep: bool = False):
        if analyzers is not None:
            self.analyzers = analyzers
        else:
            self.analyzers = default_analyzers(include_deep=include_deep)

    def run(self, sample_path: pathlib.Path, output_base: pathlib.Path, options: Dict[str,Any] = None) -> PipelineResult:
        options = options or {}
        sample_path = pathlib.Path(sample_path).resolve()
        if not sample_path.exists():
            raise FileNotFoundError(sample_path)
        output_base = pathlib.Path(output_base).resolve()
        output_base.mkdir(parents=True, exist_ok=True)

        # Deep mode: إعادة بناء المحللات لتشمل Deep
        if options.get("deep") and not any(a.name == "deep_opcode" for a in self.analyzers):
            try:
                from ..deep.opcode_analyzer import DeepOpcodeAnalyzer
                self.analyzers.append(DeepOpcodeAnalyzer())
            except:
                pass

        # Sample info
        sha256 = sha256_file(sample_path)
        sha1 = sha1_file(sample_path)
        md5 = md5_file(sample_path)
        sample_info = SampleInfo(
            path=str(sample_path),
            filename=sample_path.name,
            size_bytes=sample_path.stat().st_size,
            sha256=sha256,
            sha1=sha1,
            md5=md5,
        )
        host_info = HostInfo.collect(collect_tool_versions())

        started_at = datetime.datetime.utcnow().isoformat() + "Z"
        store = EvidenceStore.create(output_base, sha256)
        store.copy_sample(sample_path)
        # save meta
        store.save_json("meta.json", {
            "sample": sample_info.__dict__,
            "host": host_info.__dict__,
            "started_at": started_at,
            "options": options,
        })

        ctx = AnalysisContext(
            sample_path=sample_path,
            sample=sample_info,
            host=host_info,
            store=store,
            output_dir=store.run_dir,
            options=options,
        )

        result = PipelineResult(
            sample=sample_info,
            host=host_info,
            started_at=started_at,
        )

        # filter analyzers if requested
        enabled = options.get("analyzers")  # list of names or None
        analyzers_to_run = self.analyzers
        if enabled:
            analyzers_to_run = [a for a in self.analyzers if a.name in enabled]

        for analyzer in analyzers_to_run:
            ar = analyzer.run(ctx)
            result.analyzers.append(ar)
            result.findings.extend(ar.findings)
            # also save per-analyzer evidence
            ctx.store.save_json(f"evidence/{analyzer.name}/findings.json", {"findings": [f.to_dict() for f in ar.findings]})

        result.finished_at = datetime.datetime.utcnow().isoformat() + "Z"
        # Build summary
        result.summary = self._build_summary(result)
        result.comparison = ctx.shared.get("comparison_raw")

        # Save flattened findings
        store.save_json("findings.json", {"findings": [f.to_dict() for f in result.findings]})
        store.save_json("pipeline_result.json", result.to_dict())

        return result

    def _build_summary(self, result: PipelineResult) -> Dict[str,Any]:
        # Aggregate by category
        by_cat = {}
        for f in result.findings:
            by_cat.setdefault(f.category, []).append(f.to_dict())
        # confidence histogram
        from collections import Counter
        hist = Counter([f.confidence.value for f in result.findings])
        prov = Counter([f.provenance.value for f in result.findings])
        return {
            "total_findings": len(result.findings),
            "by_category": {k: len(v) for k,v in by_cat.items()},
            "confidence_histogram": dict(hist),
            "provenance_histogram": dict(prov),
            "analyzers_run": len(result.analyzers),
            "analyzers_status": {a.analyzer: a.status for a in result.analyzers},
        }
