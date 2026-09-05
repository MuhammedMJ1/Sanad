"""The scanner receives only the artifact, its runtime and static resources."""
from pathlib import Path

from docforensics_fixtures import store
from docforensics_fixtures.isolation import find_violations, run_isolated_scan, name_discloses


def test_isolated_scan_touches_nothing_under_the_bench_root(bench_root, cases):
    for rec in cases[:4]:
        cdir = store.case_dir(bench_root, rec["case_id"])
        iso = run_isolated_scan(cdir / "final.bin", rec["ext"], [bench_root.root], keep=False)
        assert iso["returncode"] == 0, iso["stderr"]
        assert iso["violations"] == []
        assert iso["result"]["tamper_status"]["state"] in ("traces_found", "no_traces_found", "no_history_available")
        for p in iso["accessed_paths"]:
            assert not Path(p).resolve().is_relative_to(bench_root.root), p
        assert name_discloses(iso["scanned_name"]) == []
        assert any(p.endswith("generators.json") for p in iso["accessed_paths"])   # static resource is allowed


def test_violation_detector_flags_ground_truth_access(bench_root, cases):
    cdir = store.case_dir(bench_root, cases[0]["case_id"])
    accessed = [{"event": "open", "path": str(cdir / "certificate.json"), "mode": "r"},
                {"event": "open", "path": "/tmp/somewhere/sample_ab12cd.pdf", "mode": "rb"},
                {"event": "open", "path": str(cdir / "original.bin"), "mode": "rb"}]
    v = find_violations(accessed, [bench_root.root])
    assert len(v) == 2
    assert find_violations([{"event": "open", "path": "/tmp/x/certificate.json", "mode": "r"}], []) != []
