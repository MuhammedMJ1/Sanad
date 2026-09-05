"""External detector results are recorded only for the exact certified bytes."""
import hashlib
import json

import pytest

from docforensics_fixtures import store
from docforensics_fixtures.benchmark import compare_external, record_external_result
from conftest import cert_of


def test_same_byte_rule(bench_root, cases):
    cid = cases[1]["case_id"]
    cert = cert_of(bench_root, cid)
    before = hashlib.sha256((store.case_dir(bench_root, cid) / "final.bin").read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        record_external_result(bench_root, cid, name="DetectorB", version="1.0", result="traces_found",
                               findings=[], artifact_sha256="0" * 64)
    path = record_external_result(bench_root, cid, name="DetectorB", version="1.0", result="no_traces_found",
                                  findings=[{"id": "b.1"}], artifact_sha256=cert["artifact"]["final_sha256"])
    doc = json.loads(path.read_text())
    assert doc["artifact_sha256"] == cert["artifact"]["final_sha256"]
    assert doc["detectors"][0]["name"] == "DetectorB"
    # record lives beside, never inside, the artifact
    assert path.parent.name == "evaluations"
    assert hashlib.sha256((store.case_dir(bench_root, cid) / "final.bin").read_bytes()).hexdigest() == before
    cmp = compare_external(bench_root, cid)
    assert cmp["ground_truth"] == cert["ground_truth"] and cmp["detectors"][0]["result"] == "no_traces_found"
