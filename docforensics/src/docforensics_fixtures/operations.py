"""Controlled operations that *naturally* leave forensic residue (natural_trace).

Each operation is something ordinary software does — an incremental PDF
save, a re-encode that keeps EXIF, a re-zip of a package. No marker is
added and no contradiction is manufactured: whatever residue the detector
finds is what the operation genuinely leaves behind. ``expect_rules`` is
declared a priori from the mechanics of the operation, not by running the
detector.
"""
from __future__ import annotations

import io
import random
import re
import struct
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from . import bases
from .bases import DocContent, PixelSpec


@dataclass
class OpResult:
    final: bytes
    content: dict[str, Any]                  # harness-side content spec after the change
    semantic_delta: dict[str, str]
    expected_observable_evidence: list[str]
    expected_unobservable_ground_truth: list[str]
    expect_rules: list[str]
    description: str
    notes: str = ""


OpFn = Callable[[bytes, dict[str, Any], str, random.Random], OpResult]


@dataclass(frozen=True)
class Operation:
    op_id: str
    kinds: frozenset[str]
    generators: frozenset[str]     # empty = any generator of those kinds
    fn: OpFn
    description: str


_OPS: dict[str, Operation] = {}


def operation(op_id: str, kinds: list[str], generators: list[str] | None = None, description: str = ""):
    def deco(fn: OpFn) -> OpFn:
        _OPS[op_id] = Operation(op_id, frozenset(kinds), frozenset(generators or []), fn, description or fn.__doc__ or "")
        return fn
    return deco


def operations_for(kind: str, generator: str) -> list[Operation]:
    return [o for o in _OPS.values() if kind in o.kinds and (not o.generators or generator in o.generators)]


def all_operations() -> list[Operation]:
    return sorted(_OPS.values(), key=lambda o: o.op_id)


# --- helpers ----------------------------------------------------------------

def _bump(iso: str, rng: random.Random) -> str:
    dt = datetime.fromisoformat(iso) + timedelta(days=rng.randint(3, 90), minutes=rng.randint(1, 500))
    return dt.isoformat(timespec="seconds")


def _new_total(doc: DocContent, rng: random.Random) -> tuple[DocContent, str]:
    old = doc.total
    parts = [int(l.rsplit(":", 1)[1].replace(",", "").split(".")[0]) for l in doc.lines]
    i = rng.randrange(len(parts))
    parts[i] += rng.randint(300, 900)
    lines = [f"{l.rsplit(':', 1)[0]}: {p:,}.00" for l, p in zip(doc.lines, parts)]
    new = DocContent(doc.title, doc.author, lines, doc.created, doc.modified, doc.reference, f"{sum(parts):,}.00")
    return new, f"line item {i + 1} and total changed {old} -> {new.total}"


def _pdf_append_update(original: bytes, replacements: dict[int, bytes], new_info: dict[str, str] | None,
                       date_dialect: str = "Z") -> bytes:
    """Append an incremental update (§7.5.6) replacing whole objects by number.

    Mimics a simple updater: classic xref subsection per object, trailer with
    /Prev, /ID carried over unchanged, new /ModDate in the updater's own
    dialect. Exactly what many lightweight PDF libraries do.
    """
    import pikepdf
    from docforensics.revisions import find_revisions
    revs = find_revisions(original)
    prev = revs[-1].startxref
    with pikepdf.open(io.BytesIO(original)) as pdf:
        trailer = pdf.trailer
        root_ref = f"{trailer['/Root'].objgen[0]} {trailer['/Root'].objgen[1]} R"
        size = int(trailer["/Size"])
        info_obj = trailer.get("/Info")
        info_ref = f"{info_obj.objgen[0]} {info_obj.objgen[1]} R" if info_obj is not None else None
        ids = trailer.get("/ID")
        id_text = None
        if ids is not None:
            id_text = "[" + " ".join("<" + bytes(x).hex() + ">" for x in ids) + "]"
        objs = dict(replacements)
        if new_info is not None and info_obj is not None:
            merged = {str(k): str(v) for k, v in pdf.docinfo.items()}
            merged.update(new_info)
            body = b"<<" + b"".join(b" %s (%s)" % (k.encode(), v.replace("(", "[").replace(")", "]").encode("latin-1", "replace"))
                                     for k, v in merged.items()) + b" >>"
            objs[info_obj.objgen[0]] = body
    out = bytearray(original)
    if not out.endswith(b"\n"):
        out += b"\n"
    offsets: dict[int, int] = {}
    for num, body in sorted(objs.items()):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    xref_off = len(out)
    out += b"xref\n"
    for num in sorted(offsets):
        out += b"%d 1\n%010d 00000 n \n" % (num, offsets[num])
    trailer_parts = [b"/Size %d" % size, b"/Root " + root_ref.encode(), b"/Prev %d" % prev]
    if info_ref:
        trailer_parts.append(b"/Info " + info_ref.encode())
    if id_text:
        trailer_parts.append(b"/ID " + id_text.encode())
    out += b"trailer\n<< " + b" ".join(trailer_parts) + b" >>\nstartxref\n%d\n%%%%EOF\n" % xref_off
    return bytes(out)


def _content_stream_objnum(original: bytes) -> int:
    import pikepdf
    with pikepdf.open(io.BytesIO(original)) as pdf:
        c = pdf.pages[0].obj["/Contents"]
        return c.objgen[0]


# --- PDF operations ----------------------------------------------------------

@operation("pdf.incremental_info_edit", ["pdf"],
           description="Change the author attribution and ModDate through an incremental update.")
def pdf_incremental_info_edit(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    doc = DocContent.from_dict(content)
    new_author = f"{rng.choice(bases.FIRST)} {rng.choice(bases.LAST)}"
    while new_author == doc.author:
        new_author = f"{rng.choice(bases.FIRST)} {rng.choice(bases.LAST)}"
    new_mod = _bump(doc.modified, rng)
    final = _pdf_append_update(original, {}, {"/Author": new_author, "/ModDate": bases._pdf_date(new_mod, "Z")})
    new = DocContent(doc.title, new_author, doc.lines, doc.created, new_mod, doc.reference, doc.total)
    has_id = b"/ID" in original
    expect = ["pdf.tamper.incremental_revisions", "pdf.tamper.recovered_prior_metadata"]
    evidence = ["second revision appended after %%EOF with /Prev chain",
                "original /Author and /ModDate physically recoverable from revision 0"]
    if has_id:
        expect.append("pdf.tamper.file_id_anomaly")
        evidence.append("/ID carried over unchanged although the file was re-saved")
    if generator == "pikepdf":
        expect += ["pdf.tamper.docinfo_xmp_divergence", "pdf.tamper.xmp_identity_anomaly",
                   "pdf.tamper.date_dialect_conflict"]
        evidence += ["XMP dc:creator / xmp:ModifyDate still carry the old values (DocInfo-only update)",
                     "new /ModDate written in the 'Z' dialect while /CreationDate uses +00'00'"]
    return OpResult(final, new.to_dict(),
                    {"kind": "metadata", "description": f"author attribution changed {doc.author!r} -> {new_author!r}; ModDate moved to {new_mod}"},
                    evidence, ["who performed the edit", "the exact editing software"], expect,
                    "incremental update rewriting /Info")


@operation("pdf.incremental_content_edit", ["pdf"],
           description="Change an amount on the page through an incremental update of the content stream.")
def pdf_incremental_content_edit(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    doc = DocContent.from_dict(content)
    new, delta = _new_total(doc, rng)
    stream = bases._page_stream(new)
    num = _content_stream_objnum(original)
    body = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
    final = _pdf_append_update(original, {num: body}, None)
    has_id = b"/ID" in original
    return OpResult(final, new.to_dict(), {"kind": "text_content", "description": delta},
                    ["second revision appended; the original content stream is still present in revision 0"]
                    + (["/ID carried over unchanged although content changed"] if has_id else []),
                    ["what the amounts were before (only the old stream bytes, not their meaning, survive)"],
                    ["pdf.tamper.incremental_revisions"] + (["pdf.tamper.file_id_anomaly"] if has_id else []),
                    "incremental update replacing the page content stream")


@operation("pdf.resave_other_tool_keep_info", ["pdf"], ["plainpdf"],
           description="Re-save through a different PDF library that preserves the original /Info (Producer unchanged).")
def pdf_resave_other_tool(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    import pikepdf
    doc = DocContent.from_dict(content)
    new, delta = _new_total(doc, rng)
    with pikepdf.open(io.BytesIO(original)) as pdf:
        pdf.pages[0].obj["/Contents"] = pdf.make_stream(bases._page_stream(new))
        buf = io.BytesIO()
        pdf.save(buf, deterministic_id=True)
    final = buf.getvalue()
    return OpResult(final, new.to_dict(), {"kind": "text_content", "description": delta},
                    ["file claims Producer 'Plainpdf 1.0' but its structure (binary comment line, "
                     "FlateDecode, trailer /ID) matches the measured pikepdf layout"],
                    ["the previous amounts (fully rewritten, no prior revision)"],
                    ["pdf.tamper.structural_fingerprint_conflict"],
                    "full rewrite by a second library that keeps DocInfo")


# --- image operations --------------------------------------------------------

def _pillow_resave_keep_exif(img: Any, exif_payload: bytes, quality: int) -> bytes:
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality, exif=exif_payload)
    return buf.getvalue()


def _exif_payload(original: bytes) -> bytes:
    from docforensics.parsers.image import parse_jpeg
    seg = next(s for s in parse_jpeg(original)["app_segments"] if s["identifier"] == "Exif")
    return original[seg["offset"] + 4: seg["offset"] + 2 + seg["length"]]


@operation("jpeg.edit_resave_keep_exif", ["jpeg"],
           description="Paint over part of the photo in an editor and re-save keeping the camera EXIF block.")
def jpeg_edit_resave(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    from PIL import Image, ImageDraw
    spec = PixelSpec.from_dict(content)
    img = Image.open(io.BytesIO(original)).convert("RGB")
    d = ImageDraw.Draw(img)
    color = (rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255))
    d.rectangle([0, 0, spec.width, spec.height // 2], fill=color)
    final = _pillow_resave_keep_exif(img, _exif_payload(original), quality=75)
    new = PixelSpec(**{**spec.to_dict(), "shapes": spec.shapes + [[0, 0, spec.width, spec.height // 2, *color]]})
    return OpResult(final, new.to_dict(),
                    {"kind": "pixels", "description": "upper half of the image painted over"},
                    ["EXIF thumbnail still shows the original picture, main image differs",
                     "JFIF APP0 now precedes APP1 and quantisation tables differ from the camera profile"],
                    ["what was in the painted region"],
                    ["image.tamper.exif_thumbnail_mismatch", "image.tamper.encoding_profile_conflict"],
                    "editor re-save that preserves EXIF")


@operation("jpeg.crop_resave_keep_exif", ["jpeg"],
           description="Crop the photo and re-save keeping the camera EXIF block.")
def jpeg_crop_resave(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    from PIL import Image
    spec = PixelSpec.from_dict(content)
    img = Image.open(io.BytesIO(original)).convert("RGB")
    crop = img.crop((0, 0, spec.width // 2, spec.height))
    final = _pillow_resave_keep_exif(crop, _exif_payload(original), quality=92)
    new = PixelSpec(**{**spec.to_dict(), "width": spec.width // 2})
    return OpResult(final, new.to_dict(), {"kind": "pixels", "description": "right half of the image cropped away"},
                    ["EXIF thumbnail aspect ratio no longer matches the image",
                     "EXIF PixelXDimension still states the original width"],
                    ["the cropped-away content"],
                    ["image.tamper.exif_thumbnail_mismatch", "image.tamper.encoding_profile_conflict"],
                    "crop + re-save that preserves EXIF")


@operation("png.edit_resave_keep_text", ["png"],
           description="Edit pixels and re-save with Pillow carrying the Software text chunk over.")
def png_edit_resave(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    from PIL import Image, ImageDraw, PngImagePlugin
    spec = PixelSpec.from_dict(content)
    img = Image.open(io.BytesIO(original)).convert("RGB")
    d = ImageDraw.Draw(img)
    color = (rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255))
    box = [10, 10, spec.width // 3, spec.height // 3]
    d.rectangle(box, fill=color)
    info = PngImagePlugin.PngInfo()
    info.add_text("Software", f"{spec.make} {spec.model}")
    buf = io.BytesIO()
    img.save(buf, "PNG", pnginfo=info)
    new = PixelSpec(**{**spec.to_dict(), "shapes": spec.shapes + [[*box, *color]]})
    return OpResult(buf.getvalue(), new.to_dict(), {"kind": "pixels", "description": "a region repainted"},
                    ["chunk layout (no tIME, Pillow ordering) does not match the writer named in the Software chunk"],
                    ["the previous pixels"], ["image.tamper.png_chunk_profile_conflict"],
                    "editor re-save carrying the Software chunk")


# --- OOXML operations --------------------------------------------------------

def _rezip(original: bytes, replace: dict[str, bytes], keep_times: bool) -> bytes:
    src = zipfile.ZipFile(io.BytesIO(original))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for zi in src.infolist():
            data = replace.get(zi.filename, src.read(zi.filename))
            if keep_times:
                nz = zipfile.ZipInfo(zi.filename, date_time=zi.date_time)
                nz.compress_type = zi.compress_type
                nz.create_system = zi.create_system
                zf.writestr(nz, data)
            else:
                zf.writestr(zi.filename, data)   # library default: current local time
    return buf.getvalue()


@operation("docx.edit_document_rezip", ["docx"],
           description="Change an amount in document.xml and re-zip with a generic ZIP library.")
def docx_edit_document(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    doc = DocContent.from_dict(content)
    new, delta = _new_total(doc, rng)
    final = _rezip(original, {"word/document.xml": bases.docx_document_xml(new)}, keep_times=False)
    return OpResult(final, new.to_dict(), {"kind": "text_content", "description": delta},
                    ["ZIP entry timestamps are the re-zip time, later than dcterms:modified",
                     "timestamps no longer uniform as the claimed application writes them"],
                    ["the previous amounts"],
                    ["ooxml.tamper.entry_timestamp_vs_core_modified", "ooxml.tamper.package_profile_conflict"],
                    "content edit + generic re-zip")


@operation("docx.metadata_edit_rezip", ["docx"],
           description="Change lastModifiedBy/modified in core.xml, re-zip preserving entry timestamps.")
def docx_metadata_edit(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    doc = DocContent.from_dict(content)
    lmb = f"{rng.choice(bases.FIRST)} {rng.choice(bases.LAST)}"
    new_mod = _bump(doc.modified, rng)
    new = DocContent(doc.title, doc.author, doc.lines, doc.created, new_mod, doc.reference, doc.total)
    final = _rezip(original, {"docProps/core.xml": bases.docx_core_xml(new, revision=1, last_modified_by=lmb)}, keep_times=True)
    return OpResult(final, new.to_dict(),
                    {"kind": "metadata", "description": f"lastModifiedBy set to {lmb!r}, modified moved to {new_mod}"},
                    ["cp:revision still 1 although modified is now well after created"],
                    ["who edited the metadata"], ["ooxml.tamper.revision_counter_anomaly"],
                    "metadata edit with timestamps preserved")


# --- further ordinary operations (each is what some real tool does) ---------

def _patch_ascii_tag(exif_payload: bytes, old: str, new: str) -> bytes:
    """In-place same-length ASCII replacement inside an EXIF block (what a
    metadata editor does when it rewrites a fixed-length tag)."""
    if len(old) != len(new):
        raise ValueError("in-place patch needs equal lengths")
    o, n = old.encode("ascii") + b"\x00", new.encode("ascii") + b"\x00"
    if o not in exif_payload:
        raise ValueError("tag value not found")
    return exif_payload.replace(o, n, 1)


@operation("jpeg.editor_updates_datetime", ["jpeg"],
           description="A metadata editor rewrites EXIF DateTime and Software in place; pixels untouched.")
def jpeg_editor_updates_datetime(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    from docforensics.parsers.image import parse_jpeg
    spec = PixelSpec.from_dict(content)
    seg = next(s for s in parse_jpeg(original)["app_segments"] if s["identifier"] == "Exif")
    start, end = seg["offset"] + 4, seg["offset"] + 2 + seg["length"]
    payload = original[start:end]
    later = (datetime.strptime(spec.captured, "%Y:%m:%d %H:%M:%S") + timedelta(days=rng.randint(2, 200))).strftime("%Y:%m:%d %H:%M:%S")
    payload = _patch_ascii_tag(payload, spec.captured, later)          # first hit is IFD0 DateTime
    payload = _patch_ascii_tag(payload, spec.software, "Acme Edit 22")  # same length as 'AI-200 v1.04'
    final = original[:start] + payload + original[end:]
    return OpResult(final, content, {"kind": "metadata", "description": f"EXIF DateTime moved to {later}; Software rewritten"},
                    ["DateTime later than DateTimeOriginal", "Software no longer the camera firmware"],
                    ["what was edited (nothing in the pixels)"],
                    ["image.tamper.datetime_inconsistency"], "in-place EXIF tag rewrite by a metadata editor")


@operation("jpeg.naive_thumbnail_strip", ["jpeg"],
           description="A privacy tool chops the EXIF block at the thumbnail IFD without fixing the pointers.")
def jpeg_naive_thumbnail_strip(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    from docforensics.parsers.image import parse_jpeg
    p = parse_jpeg(original)
    seg = next(s for s in p["app_segments"] if s["identifier"] == "Exif")
    start, end = seg["offset"] + 4, seg["offset"] + 2 + seg["length"]
    payload = original[start:end]
    tiff = payload[6:]
    # cut at the IFD1 offset (the next-IFD pointer of IFD0)
    ifd0_off = struct.unpack("<I", tiff[4:8])[0]
    (count,) = struct.unpack("<H", tiff[ifd0_off:ifd0_off + 2])
    (ifd1_off,) = struct.unpack("<I", tiff[ifd0_off + 2 + 12 * count:ifd0_off + 6 + 12 * count])
    cut = payload[:6 + ifd1_off]
    app1 = b"\xff\xe1" + struct.pack(">H", len(cut) + 2) + cut
    final = original[:seg["offset"]] + app1 + original[end:]
    return OpResult(final, content, {"kind": "metadata", "description": "embedded thumbnail bytes removed"},
                    ["IFD0 next-IFD pointer now points beyond the EXIF block"],
                    ["the thumbnail content"], ["image.tamper.makernote_integrity"],
                    "naive thumbnail strip leaving dangling offsets")


@operation("png.raw_text_patch", ["png"],
           description="A raw byte edit of the Software text chunk without recomputing the chunk CRC.")
def png_raw_text_patch(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    spec = PixelSpec.from_dict(content)
    old = f"{spec.make} {spec.model}".encode()
    new = f"{spec.make} {spec.model[:-1]}{rng.randint(0, 9)}".encode()  # same length
    assert len(old) == len(new)
    final = original.replace(b"Software\x00" + old, b"Software\x00" + new, 1)
    return OpResult(final, content, {"kind": "metadata", "description": "Software chunk text patched in place"},
                    ["tEXt chunk CRC no longer matches its bytes"], ["what the text said before"],
                    ["image.tamper.png_chunk_integrity"], "hex-editor style in-place patch")


def _rewrite_core(original: bytes, doc: DocContent, revision: int, lmb: str | None) -> bytes:
    return _rezip(original, {"docProps/core.xml": bases.docx_core_xml(doc, revision, lmb)}, keep_times=True)


@operation("docx.backdate_created_rezip", ["docx"],
           description="Rewrite dcterms:created to a date after dcterms:modified (back-dating mistake).")
def docx_backdate_created(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    doc = DocContent.from_dict(content)
    later = _bump(doc.modified, rng)
    new = DocContent(doc.title, doc.author, doc.lines, later, doc.modified, doc.reference, doc.total)
    final = _rewrite_core(original, new, 1, None)
    return OpResult(final, new.to_dict(), {"kind": "metadata", "description": f"created moved to {later}, after modified"},
                    ["dcterms:modified precedes dcterms:created"], ["the true creation date"],
                    ["ooxml.tamper.core_dates_anomaly"], "core.xml date rewrite")


@operation("docx.remove_part_rezip", ["docx"],
           description="Delete word/styles.xml from the package while its relationship and content type remain.")
def docx_remove_part(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    src = zipfile.ZipFile(io.BytesIO(original))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for zi in src.infolist():
            if zi.filename == "word/styles.xml":
                continue
            nz = zipfile.ZipInfo(zi.filename, date_time=zi.date_time)
            nz.compress_type = zi.compress_type
            nz.create_system = zi.create_system
            zf.writestr(nz, src.read(zi.filename))
    return OpResult(buf.getvalue(), content, {"kind": "package", "description": "styles part removed"},
                    ["document.xml.rels and [Content_Types].xml still point at a missing part",
                     "entry order no longer matches the application profile"],
                    ["the removed styles"], ["ooxml.tamper.relationship_inconsistency"],
                    "part deletion by a package editor")


@operation("docx.change_last_modified_by_only", ["docx"],
           description="Rewrite cp:lastModifiedBy without touching any date.")
def docx_change_lmb(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    doc = DocContent.from_dict(content)
    lmb = f"{rng.choice(bases.FIRST)} {rng.choice(bases.LAST)}"
    while lmb == doc.author:
        lmb = f"{rng.choice(bases.FIRST)} {rng.choice(bases.LAST)}"
    final = _rewrite_core(original, doc, 1, lmb)
    return OpResult(final, content, {"kind": "metadata", "description": f"lastModifiedBy set to {lmb!r}"},
                    ["lastModifiedBy differs from creator while modified == created"],
                    ["who really edited the properties"], ["ooxml.tamper.last_modified_by_anomaly"],
                    "property rewrite with dates preserved")
