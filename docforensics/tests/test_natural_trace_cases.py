"""Genuine residue is detected, and only the declared rules are required."""
from conftest import cert_of, row_of


def test_natural_trace_cases_detected_with_expected_rules(bench_root, cases, eval_report):
    seen = 0
    for rec in cases:
        cert = cert_of(bench_root, rec["case_id"])
        if cert["ground_truth"] != "modified" or cert["trace_class"] != "natural_trace":
            continue
        seen += 1
        assert cert["expect_tamper_status"] == "traces_found"
        row = row_of(eval_report, rec["case_id"])
        assert row["detector_inference"]["tamper_status"] == "traces_found", rec["case_id"]
        assert set(cert["expect_rules"]) <= set(row["detector_inference"]["fired_trace_rules"]), (
            rec["case_id"], rec["operation_ids"], row["detector_inference"]["missing_expected_rules"])
        assert row["outcome"] == "detected"
    assert seen >= 10
    m = eval_report["metrics"]
    assert m["natural_trace_detection_rate"]["value"] == 1.0
    assert m["clean_false_positive_rate"]["value"] == 0.0
    assert m["observable_trace_false_negative_rate"]["value"] == 0.0
