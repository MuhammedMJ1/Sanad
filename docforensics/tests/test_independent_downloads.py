import hashlib
import json

from docforensics_fixtures import store
from docforensics_fixtures.cli import main
from docforensics_fixtures.export import export_artifact, export_certificate
from conftest import cert_of


def _snap(path):
    return hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns


def test_artifact_alone_and_certificate_alone(bench_root, cases, tmp_path):
    cid = cases[2]["case_id"]
    cdir = store.case_dir(bench_root, cid)
    cert_before, art_before = _snap(cdir / "certificate.json"), _snap(cdir / "final.bin")
    out = export_artifact(bench_root, cid, tmp_path / "only_artifact.bin")
    assert (tmp_path / "only_artifact.bin").exists()
    assert not list(tmp_path.glob("*.json"))                       # no certificate produced
    assert out["sha256"] == cert_of(bench_root, cid)["artifact"]["final_sha256"]
    assert _snap(cdir / "certificate.json") == cert_before          # untouched
    export_certificate(bench_root, cid, tmp_path / "only_cert.json")
    assert json.loads((tmp_path / "only_cert.json").read_text())["case_id"] == cid
    assert _snap(cdir / "final.bin") == art_before                  # untouched
    assert not list(tmp_path.glob("*.zip")) and not list(tmp_path.glob("*.tar"))


def test_export_creates_exactly_two_standalone_files(bench_root, cases, tmp_path, capsys):
    cid = cases[3]["case_id"]
    rec = store.load_record(bench_root, cid)
    art = tmp_path / rec["download_name"]
    cert = tmp_path / rec["download_name"].replace("." + rec["ext"], ".certificate.json")
    rc = main(["--root", str(bench_root.root), "export", cid, "--artifact-out", str(art), "--certificate-out", str(cert)])
    assert rc == 0
    files = sorted(p.name for p in tmp_path.iterdir())
    assert files == sorted([art.name, cert.name])
    assert not any(p.is_dir() for p in tmp_path.iterdir())
    # the same neutral token pairs them and encodes nothing else
    token = art.name.split("_")[1].split(".")[0]
    assert cert.name == f"sample_{token}.certificate.json"
    assert rec["ground_truth"] not in art.name and rec["trace_class"] not in art.name
    assert hashlib.sha256(art.read_bytes()).hexdigest() == json.loads(cert.read_text())["artifact"]["final_sha256"]
