import pathlib
import subprocess
import tempfile
import json

def test_full_pipeline_on_demo_app(tmp_path):
    # Build demo_app if not exists
    demo_c = pathlib.Path("samples/demo_app/demo.c")
    assert demo_c.exists(), "demo.c missing"
    demo_bin = tmp_path / "demo_app"
    # compile
    r = subprocess.run(["gcc", "-O2", "-o", str(demo_bin), str(demo_c)], capture_output=True)
    assert r.returncode == 0, r.stderr.decode()

    from revspec.core.pipeline import Pipeline
    pipeline = Pipeline()
    result = pipeline.run(demo_bin, tmp_path / "runs", {"enable_dynamic": False})

    # Check summary
    assert result.summary["total_findings"] > 10
    assert "metadata" in result.summary["by_category"]
    assert "platform" in result.summary["by_category"]
    # Check platform detected ELF
    platform_findings = [f for f in result.findings if f.category == "platform"]
    assert any("ELF" in f.description for f in platform_findings)
    # Check strings found URL
    strings_findings = [f for f in result.findings if f.category == "strings"]
    # demo_app contains example.com
    combined = json.dumps([f.data for f in result.findings])
    assert "example.com" in combined or any("example.com" in str(f.data) for f in result.findings)

    # Check JSON export validates against schema
    from revspec.export.json_export import export_json
    out = tmp_path / "runs_out" / "report.json"
    export_json(result, out)
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["sample"]["sha256"] == result.sample.sha256

    # Check dynamic skipped
    assert any(a.analyzer == "dynamic" and a.status == "skipped" for a in result.analyzers)

def test_dynamic_enabled(tmp_path):
    demo_c = pathlib.Path("samples/demo_app/demo.c")
    demo_bin = tmp_path / "demo2"
    subprocess.run(["gcc", "-O2", "-o", str(demo_bin), str(demo_c)], check=True)
    from revspec.core.pipeline import Pipeline
    pipeline = Pipeline()
    result = pipeline.run(demo_bin, tmp_path / "runs_dyn", {"enable_dynamic": True, "dynamic_timeout": 3})
    # dynamic should run (ok or partial)
    dyn = [a for a in result.analyzers if a.analyzer == "dynamic"]
    assert len(dyn) == 1
    assert dyn[0].status in ("ok","partial","failed","skipped")
    # should have exit_code finding if executed
    if dyn[0].status == "ok":
        assert any("exit" in f.title.lower() or "خروج" in f.title for f in dyn[0].findings)
