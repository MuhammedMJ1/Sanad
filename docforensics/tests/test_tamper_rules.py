"""Rule-level behaviour on controlled inputs."""
import io
import random
import struct
import zlib

import pikepdf

from docforensics.scanner import scan_bytes
from docforensics_fixtures import bases, operations
from docforensics_fixtures.bases import DocContent


def _rules(res):
    return {f["rule_id"]: f for f in res["findings"]}


def _base(gen, seed=7):
    content = bases.make_content(bases.GENERATORS[gen].kind, random.Random(seed))
    return bases.render(gen, content), content


def test_single_revision_is_informational_only():
    data, _ = _base("pikepdf")
    res = scan_bytes(data, "sample.pdf")
    f = _rules(res)["pdf.tamper.incremental_revisions"]
    assert f["severity"] == "info" and f["is_trace"] is False
    assert res["tamper_status"]["state"] == "no_traces_found"


def test_incremental_update_reports_revisions_and_recovers_old_values():
    data, content = _base("pikepdf")
    r = operations.pdf_incremental_info_edit(data, content, "pikepdf", random.Random(1))
    res = scan_bytes(r.final, "sample.pdf")
    rules = _rules(res)
    rev = rules["pdf.tamper.incremental_revisions"]
    assert rev["is_trace"] and rev["evidence"]["revision_count"] == 2
    assert [x["start_offset"] for x in rev["evidence"]["revisions"]][0] == 0
    assert rev["evidence"]["revisions"][1]["start_offset"] == rev["evidence"]["revisions"][0]["end_offset"]
    prior = rules["pdf.tamper.recovered_prior_metadata"]
    assert prior["severity"] == "strong"
    fields = {(i["kind"], i["field"]) for i in prior["evidence"]["items"]}
    assert ("docinfo", "/Author") in fields and ("docinfo", "/ModDate") in fields
    item = next(i for i in prior["evidence"]["items"] if i["field"] == "/Author")
    assert item["old_value"] == DocContent.from_dict(content).author
    assert item["current_value"] == DocContent.from_dict(r.content).author
    assert item["source"]["revision_index"] == 0
    assert res["tamper_status"]["state"] == "traces_found"
    assert res["tamper_status"]["revisions_found"] == 2
    assert res["tamper_status"]["recovered_prior_metadata"]


def test_docinfo_xmp_divergence_ignores_timezone_formatting():
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page()
    with pdf.open_metadata(set_pikepdf_as_editor=False, update_docinfo=False) as m:
        m["xmp:CreateDate"] = "2024-01-01T10:00:00Z"
    pdf.docinfo["/CreationDate"] = "D:20240101120000+02'00'"   # same instant, other zone
    buf = io.BytesIO(); pdf.save(buf)
    res = scan_bytes(buf.getvalue(), "sample.pdf")
    assert "pdf.tamper.docinfo_xmp_divergence" not in _rules(res)
    # and a genuine semantic difference is reported
    pdf.docinfo["/CreationDate"] = "D:20240101120000Z"
    buf = io.BytesIO(); pdf.save(buf)
    res = scan_bytes(buf.getvalue(), "sample.pdf")
    f = _rules(res)["pdf.tamper.docinfo_xmp_divergence"]
    cmp = f["evidence"]["comparisons"][0]
    assert cmp["agree"] is False and cmp["docinfo_utc"] != cmp["xmp_utc"]


def test_date_dialect_conflict_is_supporting_evidence():
    data, content = _base("pikepdf")
    r = operations.pdf_incremental_info_edit(data, content, "pikepdf", random.Random(3))
    f = _rules(scan_bytes(r.final, "s.pdf"))["pdf.tamper.date_dialect_conflict"]
    assert f["severity"] == "weak"
    assert any(c["check"] == "two_dialects_within_one_file" for c in f["evidence"]["conflicts"])


def test_structural_conflict_needs_learned_profile():
    data, content = _base("plainpdf")
    r = operations.pdf_resave_other_tool(data, content, "plainpdf", random.Random(4))
    f = _rules(scan_bytes(r.final, "s.pdf"))["pdf.tamper.structural_fingerprint_conflict"]
    assert f["is_trace"] and f["evidence"]["profile_samples"] >= 5
    assert f["evidence"]["claimed_producer"].startswith("Plainpdf")
    feats = {c["feature"] for c in f["evidence"]["conflicts"]}
    assert "binary_comment" in feats
    # no profile -> informational only, never a trace
    from docforensics.structural_profile import GeneratorProfiles
    res = scan_bytes(r.final, "s.pdf", profiles=GeneratorProfiles({}, None))
    assert _rules(res)["pdf.tamper.structural_fingerprint_conflict"]["is_trace"] is False


def test_file_id_raw_evidence_separate_from_interpretation():
    data, content = _base("pikepdf")
    r = operations.pdf_incremental_content_edit(data, content, "pikepdf", random.Random(5))
    f = _rules(scan_bytes(r.final, "s.pdf"))["pdf.tamper.file_id_anomaly"]
    assert "raw" in f["evidence"] and "anomalies" in f["evidence"]
    assert f["evidence"]["raw"]["trailer_id"] is not None


def test_jpeg_thumbnail_mismatch_and_encoding_profile():
    data, content = _base("acme_camera")
    r = operations.jpeg_edit_resave(data, content, "acme_camera", random.Random(6))
    rules = _rules(scan_bytes(r.final, "s.jpg"))
    assert rules["image.tamper.exif_thumbnail_mismatch"]["severity"] in ("moderate", "strong")
    assert rules["image.tamper.encoding_profile_conflict"]["is_trace"]
    crop = operations.jpeg_crop_resave(data, content, "acme_camera", random.Random(6))
    f = _rules(scan_bytes(crop.final, "s.jpg"))["image.tamper.exif_thumbnail_mismatch"]
    assert f["severity"] == "strong" and "aspect" in f["title"]


def test_software_tag_alone_is_not_a_trace():
    data, _ = _base("acme_camera")
    f = _rules(scan_bytes(data, "s.jpg"))["image.tamper.software_editor_tag"]
    assert f["severity"] == "info" and f["is_trace"] is False


def test_png_crc_and_chunk_profile():
    data, content = _base("acme_png")
    patched = operations.png_raw_text_patch(data, content, "acme_png", random.Random(8)).final
    assert _rules(scan_bytes(patched, "s.png"))["image.tamper.png_chunk_integrity"]["severity"] == "moderate"
    resaved = operations.png_edit_resave(data, content, "acme_png", random.Random(8)).final
    assert _rules(scan_bytes(resaved, "s.png"))["image.tamper.png_chunk_profile_conflict"]["is_trace"]


def test_ooxml_rules():
    data, content = _base("acme_office")
    back = operations.docx_backdate_created(data, content, "acme_office", random.Random(9)).final
    assert _rules(scan_bytes(back, "s.docx"))["ooxml.tamper.core_dates_anomaly"]["severity"] == "strong"
    edited = operations.docx_edit_document(data, content, "acme_office", random.Random(9)).final
    rules = _rules(scan_bytes(edited, "s.docx"))
    assert "ooxml.tamper.entry_timestamp_vs_core_modified" in rules
    assert "ooxml.tamper.package_profile_conflict" in rules
    removed = operations.docx_remove_part(data, content, "acme_office", random.Random(9)).final
    f = _rules(scan_bytes(removed, "s.docx"))["ooxml.tamper.relationship_inconsistency"]
    assert "word/styles.xml" in f["evidence"]["missing"]


def test_tamper_status_never_claims_authenticity():
    from docforensics import tamper_status as ts
    for state in (ts.TRACES_FOUND, ts.NO_TRACES, ts.NO_HISTORY):
        assert "authentic" not in ts.EXPLANATION_EN[state].lower() or "not" in ts.EXPLANATION_EN[state].lower()
    res = scan_bytes(b"\x00" * 100, "blob")
    assert res["tamper_status"]["state"] == ts.NO_HISTORY
    assert res["tamper_status"]["proof_of_authenticity"] is False
    assert res["tamper_status"]["explanation_ar"]
