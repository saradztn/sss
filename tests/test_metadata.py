import pathlib
import tempfile
import json
from revspec.core.pipeline import Pipeline

def test_metadata_hashes(tmp_path):
    # create temp file
    p = tmp_path / "hello.txt"
    p.write_text("hello world")
    # run only metadata
    pipeline = Pipeline()
    # filter to metadata only via options
    result = pipeline.run(p, tmp_path / "runs", {"analyzers": ["metadata"]})
    assert result.sample.sha256 is not None
    assert len(result.sample.sha256) == 64
    # check finding exists
    ids = [f.id for f in result.findings]
    assert "meta.hash.sha256" in ids
    assert "meta.size" in ids
    # check report json valid
    d = result.to_dict()
    assert d["sample"]["filename"] == "hello.txt"

def test_metadata_file_magic(tmp_path):
    p = tmp_path / "bin"
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00"*20)
    pipeline = Pipeline()
    result = pipeline.run(p, tmp_path / "runs2", {"analyzers": ["metadata","platform"]})
    assert any(f.id == "platform.format" for f in result.findings)
