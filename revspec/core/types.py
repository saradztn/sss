"""
النماذج الأساسية — كل شيء قابل للتسلسل إلى JSON/YAML
"""
from __future__ import annotations
import dataclasses
import datetime
import hashlib
import json
import pathlib
import platform as host_platform
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .confidence import Confidence, Provenance

@dataclass
class EvidenceRef:
    """مرجع لدليل خام محفوظ على القرص"""
    path: str  # relative to run dir
    kind: str  # e.g. "raw", "log", "dump", "pcap"
    description: str = ""
    sha256: Optional[str] = None

@dataclass
class Finding:
    """
    وحدة المعلومة الذرية.
    كل حقل في التقرير النهائي مبني من Findings.
    """
    id: str
    category: str  # metadata | platform | structure | strings | behavior | ...
    title: str
    description: str
    confidence: Confidence
    provenance: Provenance
    source: str  # analyzer name + method, e.g. "metadata:hashlib.sha256"
    method: str  # كيف تم الاكتشاف
    evidence_refs: List[EvidenceRef] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "confidence": self.confidence.value,
            "provenance": self.provenance.value,
            "source": self.source,
            "method": self.method,
            "evidence_refs": [dataclasses.asdict(e) for e in self.evidence_refs],
            "data": self.data,
            "tags": self.tags,
        }

@dataclass
class AnalyzerResult:
    analyzer: str
    version: str
    started_at: str
    finished_at: str
    duration_ms: int
    status: str  # ok | partial | failed | skipped
    findings: List[Finding] = field(default_factory=list)
    artifacts: List[EvidenceRef] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)  # raw tool output subset

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analyzer": self.analyzer,
            "version": self.version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "artifacts": [dataclasses.asdict(a) for a in self.artifacts],
            "errors": self.errors,
            "warnings": self.warnings,
            "raw": self.raw,
        }

@dataclass
class SampleInfo:
    path: str
    filename: str
    size_bytes: int
    sha256: str
    sha1: str
    md5: str
    mime_type: Optional[str] = None
    collected_at: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z")

@dataclass
class HostInfo:
    os: str
    arch: str
    python_version: str
    hostname: str
    tool_versions: Dict[str, str] = field(default_factory=dict)

    @staticmethod
    def collect(tool_versions: Optional[Dict[str,str]] = None) -> "HostInfo":
        import platform
        return HostInfo(
            os=platform.platform(),
            arch=platform.machine(),
            python_version=platform.python_version(),
            hostname=platform.node(),
            tool_versions=tool_versions or {},
        )

@dataclass
class PipelineResult:
    """النتيجة الكلية لعملية التحليل"""
    schema_version: str = "1.0.0"
    sample: Optional[SampleInfo] = None
    host: Optional[HostInfo] = None
    started_at: str = ""
    finished_at: str = ""
    analyzers: List[AnalyzerResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)  # flattened
    # الملخصات المهيكلة للتقرير البشري (يتم ملؤها في مرحلة التجميع)
    summary: Dict[str, Any] = field(default_factory=dict)
    # مقارنة ثابت/ديناميكي
    comparison: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sample": dataclasses.asdict(self.sample) if self.sample else None,
            "host": dataclasses.asdict(self.host) if self.host else None,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "analyzers": [a.to_dict() for a in self.analyzers],
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "comparison": self.comparison,
        }

def sha256_file(p: pathlib.Path, chunk=8192) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def sha1_file(p: pathlib.Path) -> str:
    h = hashlib.sha1()
    with p.open("rb") as f:
        while True:
            b = f.read(8192)
            if not b: break
            h.update(b)
    return h.hexdigest()

def md5_file(p: pathlib.Path) -> str:
    h = hashlib.md5()
    with p.open("rb") as f:
        while True:
            b = f.read(8192)
            if not b: break
            h.update(b)
    return h.hexdigest()
