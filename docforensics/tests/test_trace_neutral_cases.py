"""Certified changed cases with no scanner-observable provenance evidence."""
from docforensics.signatures import identify
from docforensics_fixtures import certificate
from docforensics_fixtures.disclosure import find_disclosures
from conftest import cert_of, final_of, row_of


def test_trace_neutral_cases_are_evidence_limits(bench_root, cases, eval_report):
    seen = 0
    for rec in cases:
        cert = cert_of(bench_root, rec["case_id"])
        if cert["ground_truth"] != "modified" or cert["trace_class"] != "trace_neutral":
            continue
        seen += 1
        assert cert["original"]["sha256"] != cert["artifact"]["final_sha256"]      # externally proven change
        assert cert["semantic_delta"]["description"]
        assert cert["expected_limit"] == certificate.EVIDENCE_LIMIT
        assert cert["expect_rules"] == []
        data = final_of(bench_root, rec["case_id"])
        assert find_disclosures(data, identify(data).detected_format, [cert["case_id"]]) == []
        row = row_of(eval_report, rec["case_id"])
        assert row["detector_inference"]["tamper_status"] != "traces_found"
        assert row["outcome"] == "evidence_limit"
        assert row["evidence_limitations"]["certified_limit"] == certificate.EVIDENCE_LIMIT
    assert seen >= 4


def test_neutral_metric_is_reported_separately(eval_report):
    m = eval_report["metrics"]
    assert set(m) >= {"natural_trace_detection_rate", "clean_false_positive_rate",
                      "observable_trace_false_negative_rate", "trace_neutral_provenance_limit_rate"}
    assert "accuracy" not in " ".join(m).lower()
