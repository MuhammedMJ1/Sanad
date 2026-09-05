"""Every trace-detecting rule has at least one legitimate natural_trace positive."""
from docforensics.rules import all_rules
from conftest import cert_of


def test_every_trace_rule_has_a_natural_positive(bench_root, cases, eval_report):
    trace_rules = {r.rule_id for r in all_rules() if r.detects_trace}
    declared = set()
    fired = set()
    for rec in cases:
        cert = cert_of(bench_root, rec["case_id"])
        if cert["ground_truth"] != "modified" or cert["trace_class"] != "natural_trace":
            continue
        declared |= set(cert["expect_rules"])
        row = next(r for r in eval_report["cases"] if r["case_id"] == rec["case_id"])
        fired |= set(row["detector_inference"]["fired_trace_rules"])
    missing_declared = trace_rules - declared
    assert not missing_declared, f"trace rules without an a-priori natural positive: {sorted(missing_declared)}"
    missing_fired = trace_rules - fired
    assert not missing_fired, f"trace rules that never fired on their positive: {sorted(missing_fired)}"


def test_info_only_rules_are_flagged_as_such():
    info_rules = {r.rule_id for r in all_rules() if not r.detects_trace}
    assert {"image.tamper.software_editor_tag", "ooxml.tamper.zip_comment_present"} <= info_rules
