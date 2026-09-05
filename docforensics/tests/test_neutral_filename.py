"""Findings do not depend on the pathname; scanner-visible names disclose nothing."""
import json

from docforensics.scanner import scan_bytes
from docforensics_fixtures.isolation import name_discloses, neutral_scan_name
from docforensics_fixtures.store import neutral_name
from conftest import final_of


def _strip_input(res):
    res = json.loads(json.dumps(res))
    res.pop("input")
    return res


def test_identical_findings_under_several_neutral_names(bench_root, cases):
    for rec in cases[:6]:
        data = final_of(bench_root, rec["case_id"])
        results = [scan_bytes(data, n) for n in ("sample_4f91c2.bin", "input_b78110.dat", "object_8ac017", "x.pdf")]
        base = _strip_input(results[0])
        for r in results[1:]:
            assert _strip_input(r) == base


def test_forbidden_names_are_rejected_and_generated_names_pass(cases):
    for bad in ("tampered.pdf", "modified.pdf", "clean.pdf", "forged.docx", "reconciled.pdf", "trace_neutral.jpg",
                "pdf_docinfo_modified.pdf"):
        assert name_discloses(bad), bad
    for rec in cases:
        assert name_discloses(rec["download_name"]) == []
        assert name_discloses(neutral_name(rec["case_id"], rec["ext"])) == []
    for _ in range(20):
        assert name_discloses(neutral_scan_name("pdf")) == []
