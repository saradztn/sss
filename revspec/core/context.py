from __future__ import annotations
import pathlib
from dataclasses import dataclass, field
from typing import Dict, Any, List

from .types import SampleInfo, HostInfo
from .evidence import EvidenceStore

@dataclass
class AnalysisContext:
    sample_path: pathlib.Path
    sample: SampleInfo
    host: HostInfo
    store: EvidenceStore
    output_dir: pathlib.Path
    options: Dict[str, Any] = field(default_factory=dict)
    # shared scratch for analyzers to publish data for later stages
    shared: Dict[str, Any] = field(default_factory=dict)
    # list of analyzer names to run (None = all)
    enabled_analyzers: List[str] = field(default_factory=list)
