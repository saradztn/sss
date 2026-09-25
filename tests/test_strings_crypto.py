import pathlib
import tempfile
import subprocess

def test_strings_and_crypto(tmp_path):
    # create file with known strings
    p = tmp_path / "sample.bin"
    p.write_bytes(b"hello https://example.com/api test@example.com /etc/passwd password=123\n" + b"\x00"*100)
    from revspec.core.pipeline import Pipeline
    pipeline = Pipeline()
    result = pipeline.run(p, tmp_path / "runs", {"analyzers": ["strings","crypto"]})
    data = {f.id: f for f in result.findings}
    assert "strings.summary" in data
    # should have urls
    assert any("example.com" in str(f.data) for f in result.findings if f.id == "strings.urls")

def test_crypto_entropy(tmp_path):
    p = tmp_path / "high.bin"
    # high entropy: random bytes
    import os
    p.write_bytes(os.urandom(4096))
    from revspec.core.pipeline import Pipeline
    result = Pipeline().run(p, tmp_path / "runs2", {"analyzers": ["crypto"]})
    assert any(f.id == "crypto.high_entropy" or f.id == "crypto.normal_entropy" or f.id == "crypto.low_entropy" for f in result.findings)
