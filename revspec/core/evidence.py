"""
Evidence Store — يخزن كل الأدلة الخام والنتائج بطريقة قابلة لإعادة الإنتاج.

Layout لكل Run:
  runs/<timestamp>_<sha256[:8]>/
    ├── meta.json          # PipelineResult summary
    ├── sample.sha256
    ├── evidence/
    │   ├── <analyzer>/
    │   │   ├── raw.json
    │   │   ├── findings.json
    │   │   └── artifacts/...
    ├── raw/              # نسخة من العينة + dumps
    ├── report.md
    ├── report.json
    └── report.yaml
"""
from __future__ import annotations
import datetime
import json
import pathlib
import shutil
from typing import Dict, Any

class EvidenceStore:
    def __init__(self, run_dir: pathlib.Path):
        self.run_dir = pathlib.Path(run_dir)
        self.evidence_root = self.run_dir / "evidence"
        self.raw_root = self.run_dir / "raw"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        self.raw_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def create(base: pathlib.Path, sample_sha256: str) -> "EvidenceStore":
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        name = f"{ts}_{sample_sha256[:8]}"
        return EvidenceStore(base / name)

    def save_blob(self, rel: str, data: bytes) -> pathlib.Path:
        p = self.run_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def save_text(self, rel: str, text: str) -> pathlib.Path:
        return self.save_blob(rel, text.encode("utf-8"))

    def save_json(self, rel: str, obj: Dict[str, Any]) -> pathlib.Path:
        p = self.run_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        return p

    def copy_sample(self, sample_path: pathlib.Path) -> pathlib.Path:
        dest = self.raw_root / sample_path.name
        shutil.copy2(sample_path, dest)
        return dest

    def analyzer_dir(self, name: str) -> pathlib.Path:
        d = self.evidence_root / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "artifacts").mkdir(exist_ok=True)
        return d
