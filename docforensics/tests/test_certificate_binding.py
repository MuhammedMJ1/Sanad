import hashlib

from docforensics_fixtures import certificate
from conftest import cert_of, final_of, original_of


def test_hashes_bind_artifact_and_original(bench_root, cases):
    for rec in cases:
        cert = cert_of(bench_root, rec["case_id"])
        final, original = final_of(bench_root, rec["case_id"]), original_of(bench_root, rec["case_id"])
        assert hashlib.sha256(final).hexdigest() == cert["artifact"]["final_sha256"]
        assert len(final) == cert["artifact"]["size_bytes"]
        assert hashlib.sha256(original).hexdigest() == cert["original"]["sha256"]
        v = certificate.verify(final, cert, original)
        assert v["certificate_valid"] and v["artifact_hash_match"] and v["original_hash_match"] and v["integrity_valid"]
        if cert["ground_truth"] == "modified":
            assert cert["original"]["sha256"] != cert["artifact"]["final_sha256"]
        else:
            assert cert["original"]["sha256"] == cert["artifact"]["final_sha256"]


def test_certificate_schema(bench_root, cases):
    keys = {"certificate_version", "case_id", "artifact", "original", "ground_truth", "trace_class",
            "controlled_operations", "semantic_delta", "expected_observable_evidence",
            "expected_unobservable_ground_truth", "expect_rules", "expect_tamper_status", "expected_limit",
            "generated_at", "notes", "integrity"}
    for rec in cases:
        cert = cert_of(bench_root, rec["case_id"])
        assert keys <= set(cert)
        assert cert["artifact"]["download_name"].startswith("sample_")
        assert cert["expected_limit"] in (None, certificate.EVIDENCE_LIMIT)
