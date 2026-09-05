import hashlib
import shutil

from docforensics.scanner import scan_file
from docforensics_fixtures import store
from docforensics_fixtures.export import export_artifact
from conftest import cert_of


def test_hash_identical_through_every_stage(bench_root, cases, tmp_path):
    for rec in cases:
        cid = rec["case_id"]
        expected = cert_of(bench_root, cid)["artifact"]["final_sha256"]
        assert rec["final_sha256"] == expected                                       # at generation
        stored = store.case_dir(bench_root, cid) / "final.bin"
        assert hashlib.sha256(stored.read_bytes()).hexdigest() == expected          # before export
        out = export_artifact(bench_root, cid, tmp_path / f"{cid}.bin")
        assert out["sha256"] == expected                                             # after export
        dl = tmp_path / f"dl_{rec['download_name']}"
        shutil.copyfile(tmp_path / f"{cid}.bin", dl)                                 # user-facing download
        assert hashlib.sha256(dl.read_bytes()).hexdigest() == expected
        res = scan_file(str(dl))
        assert res["input"]["sha256"] == expected                                    # what the scanner saw
        assert hashlib.sha256(dl.read_bytes()).hexdigest() == expected              # scan left it unchanged
