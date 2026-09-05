from docforensics_fixtures import certificate
from docforensics_fixtures.cli import main
from docforensics_fixtures.export import export_artifact, export_certificate
from conftest import cert_of, final_of


def test_swapped_certificates_fail_verification(bench_root, cases):
    a, b = cases[0]["case_id"], cases[1]["case_id"]
    va = certificate.verify(final_of(bench_root, a), cert_of(bench_root, b))
    vb = certificate.verify(final_of(bench_root, b), cert_of(bench_root, a))
    assert not va["artifact_hash_match"] and not va["certificate_valid"]
    assert not vb["artifact_hash_match"] and not vb["certificate_valid"]
    assert any("refused" in r for r in va["reasons"])


def test_cli_verify_certificate_refuses_swap(bench_root, cases, tmp_path, capsys):
    a, b = cases[0]["case_id"], cases[1]["case_id"]
    export_artifact(bench_root, a, tmp_path / "x.bin")
    export_certificate(bench_root, b, tmp_path / "y.certificate.json")
    export_certificate(bench_root, a, tmp_path / "x.certificate.json")
    rc = main(["--root", str(bench_root.root), "verify-certificate", "--artifact", str(tmp_path / "x.bin"),
               "--certificate", str(tmp_path / "y.certificate.json")])
    assert rc == 5 and "artifact_hash_match: false" in capsys.readouterr().out
    rc = main(["--root", str(bench_root.root), "verify-certificate", "--artifact", str(tmp_path / "x.bin"),
               "--certificate", str(tmp_path / "x.certificate.json")])
    out = capsys.readouterr().out
    assert rc == 0 and "artifact_hash_match: true" in out and "certificate_valid: true" in out
