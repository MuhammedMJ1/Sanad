import copy

from docforensics_fixtures import certificate
from conftest import cert_of, final_of


def test_mutated_field_breaks_integrity(bench_root, cases):
    cid = cases[0]["case_id"]
    cert = copy.deepcopy(cert_of(bench_root, cid))
    cert["ground_truth"] = "unmodified" if cert["ground_truth"] == "modified" else "modified"
    v = certificate.verify(final_of(bench_root, cid), cert)
    assert v["artifact_hash_match"] and not v["integrity_valid"] and not v["certificate_valid"]


def test_one_byte_change_breaks_binding(bench_root, cases):
    cid = cases[0]["case_id"]
    data = bytearray(final_of(bench_root, cid))
    data[len(data) // 2] ^= 0x01
    v = certificate.verify(bytes(data), cert_of(bench_root, cid))
    assert not v["artifact_hash_match"] and not v["certificate_valid"]
    assert v["integrity_valid"]   # the certificate itself is intact
