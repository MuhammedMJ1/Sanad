"""The scanner result and its environment never contain benchmark truth."""
import json

from docforensics_fixtures.isolation import clean_env, env_discloses
from conftest import cert_of, row_of


def test_scanner_output_contains_no_ground_truth(bench_root, cases, eval_report):
    from docforensics.scanner import scan_bytes
    from conftest import final_of
    for rec in cases:
        cert = cert_of(bench_root, rec["case_id"])
        res = scan_bytes(final_of(bench_root, rec["case_id"]), "sample.bin")
        blob = json.dumps(res, ensure_ascii=False)
        tokens = [cert["case_id"], "trace_neutral", "natural_trace", "expect_rules", "ground_truth", "certificate"]
        if "_" in rec["generator"]:
            tokens.append(rec["generator"])   # harness-only label; 'pikepdf' is the file's own Producer
        if cert["original"]["sha256"] != cert["artifact"]["final_sha256"]:
            tokens.append(cert["original"]["sha256"])      # the scanner may only know the bytes it was given
        for token in tokens:
            assert token not in blob, (rec["case_id"], token)
        for op in cert["controlled_operations"]:
            assert op["operation_id"] not in blob


def test_isolated_scanner_env_discloses_nothing(bench_root, cases, tmp_path):
    env = clean_env(tmp_path)
    cert = cert_of(bench_root, cases[0]["case_id"])
    assert env_discloses(env, [cert["case_id"], cert["artifact"]["final_sha256"], cert["original"]["sha256"],
                              str(bench_root.root)]) == []
    assert env_discloses({"DOCFORENSICS_CASE": "x"}, []) == ["DOCFORENSICS_CASE"]


def test_certificate_is_never_passed_to_scanner(bench_root, cases, eval_report):
    for rec in cases:
        row = row_of(eval_report, rec["case_id"])
        assert row["outcome"] not in ("scanner_error", "certificate_invalid", "same_byte_violation")
    for iso in eval_report["isolation"]:
        assert iso["violations"] == [], iso
