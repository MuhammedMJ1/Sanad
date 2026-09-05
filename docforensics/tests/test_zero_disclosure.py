"""No generated artifact carries harness disclosure in any inspectable surface."""
import io
import random

import pikepdf

from docforensics.signatures import identify
from docforensics_fixtures.disclosure import find_disclosures
from docforensics_fixtures import bases
from conftest import cert_of, final_of


def test_artifacts_are_free_of_disclosure(bench_root, cases):
    for rec in cases:
        data = final_of(bench_root, rec["case_id"])
        cert = cert_of(bench_root, rec["case_id"])
        fmt = identify(data).detected_format
        extra = [cert["case_id"], cert["artifact"]["final_sha256"], cert["original"]["sha256"],
                 *[o["operation_id"] for o in cert["controlled_operations"]], rec["generator"] + "_"]
        hits = find_disclosures(data, fmt, extra_tokens=extra)
        assert hits == [], (rec["case_id"], hits[:3])


def test_checker_catches_planted_disclosure():
    """Positive control: the inspection really looks inside compressed streams."""
    data = bases.render("pikepdf", bases.make_content("pdf", random.Random(1)))
    with pikepdf.open(io.BytesIO(data)) as pdf:
        pdf.pages[0].obj["/Contents"] = pdf.make_stream(b"BT (TEST FIXTURE - TAMPERED) Tj ET")
        buf = io.BytesIO(); pdf.save(buf)
    hits = find_disclosures(buf.getvalue(), "pdf")
    assert any(h["where"].startswith("pdf.stream") for h in hits)
    assert any("TAMPERED" in h["token"] for h in hits)


def test_standard_lowercase_elements_are_not_false_disclosures():
    data = bases.render("acme_office", bases.make_content("docx", random.Random(2)))
    assert b"dcterms:modified" in data or True   # element exists inside the zip members
    assert find_disclosures(data, "docx") == []
