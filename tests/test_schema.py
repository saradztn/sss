import pathlib
import json
import subprocess
import tempfile

def test_schema_validation():
    demo_c = pathlib.Path("samples/demo_app/demo.c")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_p = pathlib.Path(tmp)
        demo_bin = tmp_p / "demo_app"
        subprocess.run(["gcc","-O2","-o",str(demo_bin), str(demo_c)], check=True)
        from revspec.core.pipeline import Pipeline
        pipeline = Pipeline()
        result = pipeline.run(demo_bin, tmp_p / "runs", {})
        data = result.to_dict()
        # validate against schema if jsonschema available
        try:
            import jsonschema
            schema = json.loads(pathlib.Path("schemas/report.schema.json").read_text())
            jsonschema.validate(instance=data, schema=schema)
        except ImportError:
            # fallback: just check required keys
            assert "schema_version" in data
            assert "sample" in data
            assert "findings" in data
            for f in data["findings"]:
                assert "confidence" in f
                assert "provenance" in f
                assert "source" in f
                assert "method" in f

def test_confidence_provenance_distinction():
    from revspec.core.confidence import Confidence, Provenance, provenance_for
    assert provenance_for(Confidence.PROVEN) == Provenance.OBSERVED
    assert provenance_for(Confidence.HIGH) == Provenance.INFERRED
    assert provenance_for(Confidence.UNKNOWN) == Provenance.UNDETERMINED
