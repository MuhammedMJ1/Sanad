"""Zero-disclosure inspection of a generated artifact.

Extracts every scanner-readable text surface of an artifact (raw bytes,
decompressed PDF streams, DocInfo/XMP, OOXML members and names, ZIP comment
and extra fields, PNG text chunks, JPEG APP segments) and searches it for
harness vocabulary and case-specific identifiers. Used by the builder as a
refusal gate and by the tests as an independent check.
"""
from __future__ import annotations

import io
import re
import zipfile
import zlib
from typing import Any

# Upper-case harness words: matched case-sensitively so that standard
# lower-case element names (dcterms:modified, /ModDate) never trigger.
DISCLOSURE_WORDS = ["SYNTHETIC", "TEST FIXTURE", "TAMPERED", "MODIFIED", "RECONCILED", "ADVERSARIAL",
                    "GROUND TRUTH", "GROUND_TRUTH", "FIXTURE", "BENCHMARK", "HARNESS", "CASE_ID",
                    "TRACE_NEUTRAL", "NATURAL_TRACE", "EXPECT_RULES", "CERTIFICATE"]
# Arabic equivalents.
DISCLOSURE_WORDS_AR = ["مزيف", "معدّل", "معدل", "اختبار", "حقيقة أرضية", "مُعدَّل", "مزوّر", "مزور"]
# Case-insensitive tokens that are harness identifiers wherever they appear.
DISCLOSURE_TOKENS = ["docforensics", "trace_neutral", "natural_trace", "expect_rules", "case_id",
                     "ground_truth", "certificate.json"]


def _pdf_surfaces(data: bytes) -> list[tuple[str, str]]:
    out = []
    try:
        import pikepdf
        with pikepdf.open(io.BytesIO(data)) as pdf:
            for obj in pdf.objects:
                try:
                    if isinstance(obj, pikepdf.Stream):
                        out.append(("pdf.stream", bytes(obj.read_bytes()).decode("latin-1", "replace")))
                    else:
                        out.append(("pdf.object", str(obj)))
                except Exception:
                    continue
            out.append(("pdf.docinfo", str(dict(pdf.docinfo))))
            out.append(("pdf.trailer", str(pdf.trailer)))
    except Exception:
        pass
    return out


def _ooxml_surfaces(data: bytes) -> list[tuple[str, str]]:
    out = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            out.append(("zip.comment", zf.comment.decode("utf-8", "replace")))
            for zi in zf.infolist():
                out.append(("zip.name", zi.filename))
                out.append(("zip.extra", zi.extra.decode("latin-1", "replace")))
                out.append(("zip.comment.entry", zi.comment.decode("utf-8", "replace")))
                try:
                    out.append((f"zip.member:{zi.filename}", zf.read(zi.filename).decode("utf-8", "replace")))
                except Exception:
                    continue
    except zipfile.BadZipFile:
        pass
    return out


def _png_surfaces(data: bytes) -> list[tuple[str, str]]:
    from docforensics.parsers.image import parse_png
    p = parse_png(data)
    out = [("png.text", f"{k}={v}") for k, v in p.get("text_chunks", {}).items()]
    for c in p.get("chunks", []):
        if c["type"] not in ("IDAT", "IHDR", "IEND"):
            body = data[c["offset"] + 8:c["offset"] + 8 + c["length"]]
            out.append((f"png.chunk:{c['type']}", body.decode("latin-1", "replace")))
            try:
                out.append((f"png.chunk.inflated:{c['type']}", zlib.decompress(body.split(b"\x00", 1)[-1][1:]).decode("latin-1", "replace")))
            except Exception:
                pass
    return out


def _jpeg_surfaces(data: bytes) -> list[tuple[str, str]]:
    from docforensics.parsers.image import parse_jpeg
    p = parse_jpeg(data)
    out = []
    for s in p.get("app_segments", []):
        out.append((f"jpeg.{s['marker']}:{s['identifier']}", data[s["offset"]:s["offset"] + 2 + s["length"]].decode("latin-1", "replace")))
    return out


def surfaces(data: bytes, detected_format: str) -> list[tuple[str, str]]:
    out = [("raw", data.decode("latin-1", "replace"))]
    if detected_format == "pdf":
        out += _pdf_surfaces(data)
    elif detected_format in ("docx", "xlsx", "pptx", "zip"):
        out += _ooxml_surfaces(data)
    elif detected_format == "png":
        out += _png_surfaces(data)
    elif detected_format == "jpeg":
        out += _jpeg_surfaces(data)
    return out


def find_disclosures(data: bytes, detected_format: str, extra_tokens: list[str] = ()) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    words = [re.compile(r"\b" + re.escape(w) + r"\b") for w in DISCLOSURE_WORDS]
    tokens = [t.lower() for t in list(DISCLOSURE_TOKENS) + [t for t in extra_tokens if t]]
    for where, text in surfaces(data, detected_format):
        for rx in words:
            if rx.search(text):
                hits.append({"where": where, "token": rx.pattern, "kind": "word"})
        for w in DISCLOSURE_WORDS_AR:
            if w in text:
                hits.append({"where": where, "token": w, "kind": "word_ar"})
        low = text.lower()
        for t in tokens:
            if len(t) >= 6 and t in low:
                hits.append({"where": where, "token": t, "kind": "token"})
    return hits
