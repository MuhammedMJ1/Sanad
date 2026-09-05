"""``docforensics scan`` accepts any file read-only, regardless of extension."""
import hashlib
import io
import json
import random
import zipfile

from docforensics.cli import main
from docforensics_fixtures import bases


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def _scan(path, capsys):
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    rc = main(["scan", str(path), "--json", "-"])
    out = json.loads(capsys.readouterr().out)
    after = hashlib.sha256(path.read_bytes()).hexdigest()
    assert before == after, "scan modified its input"
    assert rc == 0
    return out


def test_intake_matrix(tmp_path, capsys):
    pdf = bases.render("pikepdf", bases.make_content("pdf", random.Random(1)))
    jpg = bases.render("acme_camera", bases.make_content("jpeg", random.Random(1)))
    docx = bases.render("acme_office", bases.make_content("docx", random.Random(1)))
    assert _scan(_write(tmp_path, "a.pdf", pdf), capsys)["input"]["detected_format"] == "pdf"
    r = _scan(_write(tmp_path, "nosuffix", pdf), capsys)
    assert r["input"]["detected_format"] == "pdf" and r["input"]["extension_hint"] is None
    r = _scan(_write(tmp_path, "photo.jpg", pdf), capsys)
    assert r["input"]["detected_format"] == "pdf" and r["input"]["extension_agrees_with_content"] is False
    r = _scan(_write(tmp_path, "blob.bin", jpg), capsys)
    assert r["input"]["detected_format"] == "jpeg" and r["tamper_status"]["state"] == "no_traces_found"
    r = _scan(_write(tmp_path, "notes.txt", docx), capsys)
    assert r["input"]["detected_format"] == "docx" and "ooxml" in r["parsers"]
    rng = random.Random(3)
    r = _scan(_write(tmp_path, "mystery.dat", bytes(rng.randrange(256) for _ in range(4096))), capsys)
    assert r["input"]["detected_format"] == "unknown"
    assert any(l["family"] == "unsupported_format" for l in r["analysis_limits"])
    assert r["generic"]["shannon_entropy"] > 7
    r = _scan(_write(tmp_path, "empty.pdf", b""), capsys)
    assert r["input"]["detected_format"] == "empty" and r["tamper_status"]["state"] == "no_history_available"
    r = _scan(_write(tmp_path, "broken.docx", docx[: len(docx) // 2]), capsys)   # truncated container
    assert r["input"]["detected_format"] in ("zip", "docx", "unknown")
    assert r["analysis_limits"], "a malformed container must report a limit"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "plain archive")
    r = _scan(_write(tmp_path, "archive.docx", buf.getvalue()), capsys)
    assert r["input"]["detected_format"] == "zip" and r["analysis_limits"]


def test_missing_file_and_directory(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "nope.pdf")]) == 2
    assert main(["scan", str(tmp_path)]) == 2


def test_html_report(tmp_path, capsys):
    p = _write(tmp_path, "x.pdf", bases.render("plainpdf", bases.make_content("pdf", random.Random(2))))
    assert main(["scan", str(p), "--html", str(tmp_path / "r.html")]) == 0
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert "tamper_status" in html and "<script" not in html
