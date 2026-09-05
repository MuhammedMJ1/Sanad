"""Clean base artifacts, generated deterministically from a seed.

Every generator here stands for one *claimed producer* and writes its format
in one fixed way, so the structural profiles learned from these files are
genuinely empirical. Content is ordinary business prose with no harness
vocabulary. Vendor names are fictitious ("Acme ...") so learned profiles can
never collide with real-world producers.
"""
from __future__ import annotations

import io
import random
import struct
import zipfile
import zlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any

FIRST = ["Lina", "Omar", "Sara", "Karim", "Nadia", "Yusuf", "Maya", "Tariq", "Hana", "Rami"]
LAST = ["Haddad", "Mansour", "Khalil", "Saleh", "Farah", "Nasser", "Aziz", "Barakat", "Hamdan", "Qasim"]
ITEMS = ["Consulting services", "Server maintenance", "Design review", "Training session",
         "Licence renewal", "Network audit", "Content translation", "Site survey"]

# --- content specs ------------------------------------------------------------

@dataclass
class DocContent:
    title: str
    author: str
    lines: list[str]
    created: str            # ISO 8601 UTC
    modified: str
    reference: str
    total: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DocContent":
        return cls(**d)


@dataclass
class PixelSpec:
    width: int
    height: int
    seed: int
    shapes: list[list[int]]          # [x0, y0, x1, y1, r, g, b]
    captured: str                    # "YYYY:MM:DD HH:MM:SS"
    make: str = "Acme Imaging"
    model: str = "AI-200"
    software: str = "AI-200 v1.04"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PixelSpec":
        return cls(**d)


def _dt(rng: random.Random) -> datetime:
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    return base + timedelta(days=rng.randint(0, 600), hours=rng.randint(7, 18), minutes=rng.randint(0, 59))


def doc_content(rng: random.Random) -> DocContent:
    author = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
    ref = f"INV-{rng.randint(1000, 9999)}"
    created = _dt(rng)
    n = rng.randint(2, 4)
    lines, total = [], 0
    for _ in range(n):
        amount = rng.randint(120, 2400)
        total += amount
        lines.append(f"{rng.choice(ITEMS)}: {amount:,}.00")
    return DocContent(
        title=f"Statement {ref}", author=author, lines=lines,
        created=created.isoformat(timespec="seconds"), modified=created.isoformat(timespec="seconds"),
        reference=ref, total=f"{total:,}.00",
    )


def pixel_spec(rng: random.Random, width: int = 320, height: int = 240) -> PixelSpec:
    shapes = []
    for _ in range(rng.randint(3, 6)):
        x0, y0 = rng.randint(0, width - 40), rng.randint(0, height - 40)
        shapes.append([x0, y0, x0 + rng.randint(20, 120), y0 + rng.randint(20, 100),
                       rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255)])
    cap = _dt(rng)
    return PixelSpec(width, height, rng.randint(0, 2**31), shapes, cap.strftime("%Y:%m:%d %H:%M:%S"))


# --- PDF: two producers ------------------------------------------------------

def _pdf_date(iso: str, dialect: str) -> str:
    dt = datetime.fromisoformat(iso).astimezone(timezone.utc)
    core = dt.strftime("D:%Y%m%d%H%M%S")
    return core + ("Z" if dialect == "Z" else "+00'00'")


def _page_stream(doc: DocContent) -> bytes:
    y = 760
    parts = [b"BT /F1 14 Tf 72 %d Td (%s) Tj ET" % (y, doc.title.encode("latin-1", "replace"))]
    y -= 30
    for line in [f"Prepared by {doc.author}", *doc.lines, f"Total due: {doc.total}"]:
        parts.append(b"BT /F1 11 Tf 72 %d Td (%s) Tj ET" % (y, line.replace("(", "[").replace(")", "]").encode("latin-1", "replace")))
        y -= 18
    return b"\n".join(parts)


def render_pdf_pikepdf(doc: DocContent) -> bytes:
    """Producer 'pikepdf': qpdf-style structure, XMP synced with DocInfo."""
    import pikepdf
    pdf = pikepdf.Pdf.new()
    font = pdf.make_indirect(pikepdf.Dictionary(Type=pikepdf.Name.Font, Subtype=pikepdf.Name.Type1,
                                                BaseFont=pikepdf.Name.Helvetica))
    page = pikepdf.Dictionary(Type=pikepdf.Name.Page, MediaBox=[0, 0, 612, 792],
                              Resources=pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font)),
                              Contents=pdf.make_stream(_page_stream(doc)))
    pdf.pages.append(pikepdf.Page(page))
    producer = f"pikepdf {pikepdf.__version__}"
    with pdf.open_metadata(set_pikepdf_as_editor=False, update_docinfo=False) as m:
        m["dc:title"] = doc.title
        m["dc:creator"] = [doc.author]
        m["xmp:CreatorTool"] = "Acme Ledger 2.4"
        m["pdf:Producer"] = producer
        m["xmp:CreateDate"] = doc.created
        m["xmp:ModifyDate"] = doc.modified
        m["xmp:MetadataDate"] = doc.modified
    pdf.docinfo["/Title"] = doc.title
    pdf.docinfo["/Author"] = doc.author
    pdf.docinfo["/Creator"] = "Acme Ledger 2.4"
    pdf.docinfo["/Producer"] = producer
    pdf.docinfo["/CreationDate"] = _pdf_date(doc.created, "+")
    pdf.docinfo["/ModDate"] = _pdf_date(doc.modified, "+")
    buf = io.BytesIO()
    pdf.save(buf, deterministic_id=True)
    return buf.getvalue()


def render_pdf_plain(doc: DocContent) -> bytes:
    """Producer 'Plainpdf 1.0': hand-built classic xref, Z dates, no /ID, no XMP."""
    content = _page_stream(doc)
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /Title (%s) /Author (%s) /Creator (Acme Ledger 2.4) /Producer (Plainpdf 1.0) /CreationDate (%s) /ModDate (%s) >>" % (
            doc.title.encode("latin-1", "replace"), doc.author.encode("latin-1", "replace"),
            _pdf_date(doc.created, "Z").encode(), _pdf_date(doc.modified, "Z").encode()),
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


# --- images: a fictitious camera and a fictitious PNG writer -------------------

def render_pixels(spec: PixelSpec) -> Any:
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (spec.width, spec.height))
    px = img.load()
    for y in range(spec.height):
        for x in range(spec.width):
            px[x, y] = ((x * 255) // spec.width, (y * 255) // spec.height, (spec.seed + x + y) % 256)
    d = ImageDraw.Draw(img)
    for x0, y0, x1, y1, r, g, b in spec.shapes:
        d.rectangle([x0, y0, x1, y1], fill=(r, g, b))
    return img


def _ascii(s: str) -> bytes:
    return s.encode("ascii", "replace") + b"\x00"


def _ifd(entries: list[tuple[int, int, int, bytes]], ifd_offset: int, next_ifd: int) -> bytes:
    """Serialise little-endian IFD entries + their overflow data block."""
    entries = sorted(entries)
    head_len = 2 + 12 * len(entries) + 4
    data = bytearray()
    body = bytearray(struct.pack("<H", len(entries)))
    for tag, typ, count, payload in entries:
        if len(payload) <= 4:
            body += struct.pack("<HHI", tag, typ, count) + payload.ljust(4, b"\x00")
        else:
            body += struct.pack("<HHII", tag, typ, count, ifd_offset + head_len + len(data))
            data += payload
            if len(data) % 2:
                data += b"\x00"
    body += struct.pack("<I", next_ifd)
    return bytes(body) + bytes(data)


def build_exif(spec: PixelSpec, thumbnail: bytes | None, datetime_tag: str | None = None,
               software: str | None = None) -> bytes:
    """TIFF block (IFD0 + Exif IFD + IFD1 thumbnail) as a camera would write it."""
    dt = datetime_tag or spec.captured
    sw = software if software is not None else spec.software
    ifd0 = [
        (0x010F, 2, len(_ascii(spec.make)), _ascii(spec.make)),
        (0x0110, 2, len(_ascii(spec.model)), _ascii(spec.model)),
        (0x0112, 3, 1, struct.pack("<H", 1)),
        (0x0131, 2, len(_ascii(sw)), _ascii(sw)),
        (0x0132, 2, len(_ascii(dt)), _ascii(dt)),
        (0x8769, 4, 1, b"\x00\x00\x00\x00"),  # patched below
    ]
    ifd0_len = 2 + 12 * len(ifd0) + 4 + sum(len(p) + len(p) % 2 for *_, p in ifd0 if len(p) > 4)
    exif_off = 8 + ifd0_len
    makernote = bytes((spec.seed >> (i % 24)) & 0xFF for i in range(64))
    exif = [
        (0x9000, 7, 4, b"0230"),
        (0x9003, 2, len(_ascii(spec.captured)), _ascii(spec.captured)),
        (0x9004, 2, len(_ascii(spec.captured)), _ascii(spec.captured)),
        (0x927C, 7, len(makernote), makernote),
        (0xA002, 4, 1, struct.pack("<I", spec.width)),
        (0xA003, 4, 1, struct.pack("<I", spec.height)),
    ]
    exif_len = 2 + 12 * len(exif) + 4 + sum(len(p) + len(p) % 2 for *_, p in exif if len(p) > 4)
    ifd1_off = exif_off + exif_len if thumbnail else 0
    ifd0[-1] = (0x8769, 4, 1, struct.pack("<I", exif_off))
    tiff = bytearray(b"II*\x00" + struct.pack("<I", 8))
    tiff += _ifd(ifd0, 8, ifd1_off)
    tiff += _ifd(exif, exif_off, 0)
    if thumbnail:
        ifd1 = [
            (0x0103, 3, 1, struct.pack("<H", 6)),
            (0x0201, 4, 1, b"\x00\x00\x00\x00"),
            (0x0202, 4, 1, struct.pack("<I", len(thumbnail))),
        ]
        ifd1_len = 2 + 12 * len(ifd1) + 4
        ifd1[1] = (0x0201, 4, 1, struct.pack("<I", ifd1_off + ifd1_len))
        tiff += _ifd(ifd1, ifd1_off, 0)
        tiff += thumbnail
    return bytes(tiff)


def _jpeg_segments(data: bytes) -> list[tuple[int, bytes]]:
    """Split a JPEG into (marker, segment-bytes-including-marker) up to and including SOS+scan."""
    segs, pos = [], 2
    while pos + 4 <= len(data):
        marker = data[pos + 1]
        if marker == 0xDA:
            segs.append((marker, data[pos:]))
            break
        (seglen,) = struct.unpack(">H", data[pos + 2:pos + 4])
        segs.append((marker, data[pos:pos + 2 + seglen]))
        pos += 2 + seglen
    return segs


def assemble_camera_jpeg(img: Any, spec: PixelSpec, quality: int = 92, datetime_tag: str | None = None,
                         software: str | None = None) -> bytes:
    """Encode like the fictitious camera: APP1 EXIF first, no JFIF, fixed quality, thumbnail."""
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality, subsampling=2)
    body = [s for m, s in _jpeg_segments(buf.getvalue()) if m != 0xE0]
    th = img.copy()
    th.thumbnail((160, 120))
    tb = io.BytesIO()
    th.save(tb, "JPEG", quality=70)
    thumb = b"".join(s for m, s in _jpeg_segments(tb.getvalue()) if m != 0xE0)
    thumb = b"\xff\xd8" + thumb
    exif = b"Exif\x00\x00" + build_exif(spec, thumb, datetime_tag, software)
    app1 = b"\xff\xe1" + struct.pack(">H", len(exif) + 2) + exif
    return b"\xff\xd8" + app1 + b"".join(body)


def render_jpeg_camera(spec: PixelSpec) -> bytes:
    return assemble_camera_jpeg(render_pixels(spec), spec)


def _png_chunk(ctype: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF)


def assemble_acme_png(img: Any, spec: PixelSpec) -> bytes:
    """The fictitious 'Acme Imaging' PNG writer: IHDR, tEXt Software, tIME, IDAT..., IEND."""
    buf = io.BytesIO()
    img.save(buf, "PNG", compress_level=6)
    data = buf.getvalue()
    chunks, pos = [], 8
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        chunks.append((ctype, data[pos + 8:pos + 8 + length]))
        pos += 12 + length
    ihdr = next(b for t, b in chunks if t == b"IHDR")
    idats = [b for t, b in chunks if t == b"IDAT"]
    dt = datetime.strptime(spec.captured, "%Y:%m:%d %H:%M:%S")
    out = bytearray(b"\x89PNG\r\n\x1a\n")
    out += _png_chunk(b"IHDR", ihdr)
    out += _png_chunk(b"tEXt", b"Software\x00" + f"{spec.make} {spec.model}".encode())
    out += _png_chunk(b"tIME", struct.pack(">HBBBBB", dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second))
    for b in idats:
        out += _png_chunk(b"IDAT", b)
    out += _png_chunk(b"IEND", b"")
    return bytes(out)


def render_png_acme(spec: PixelSpec) -> bytes:
    return assemble_acme_png(render_pixels(spec), spec)


# --- OOXML: a fictitious office application ---------------------------------

_CT = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>"""
_RELS = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>"""
_DOC_RELS = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>"""
_STYLES = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style></w:styles>"""


def _xml_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def docx_document_xml(doc: DocContent) -> bytes:
    paras = [doc.title, f"Prepared by {doc.author}", *doc.lines, f"Total due: {doc.total}"]
    body = "".join(f"<w:p><w:r><w:t xml:space=\"preserve\">{_xml_escape(p)}</w:t></w:r></w:p>" for p in paras)
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}</w:body></w:document>').encode("utf-8")


def docx_core_xml(doc: DocContent, revision: int = 1, last_modified_by: str | None = None) -> bytes:
    lmb = last_modified_by or doc.author
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>{_xml_escape(doc.title)}</dc:title><dc:creator>{_xml_escape(doc.author)}</dc:creator><cp:lastModifiedBy>{_xml_escape(lmb)}</cp:lastModifiedBy><cp:revision>{revision}</cp:revision><dcterms:created xsi:type="dcterms:W3CDTF">{doc.created.replace("+00:00", "Z")}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">{doc.modified.replace("+00:00", "Z")}</dcterms:modified></cp:coreProperties>').encode("utf-8")


def docx_app_xml(doc: DocContent) -> bytes:
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Acme Office</Application><AppVersion>3.1</AppVersion><Words>{sum(len(l.split()) for l in doc.lines) + 6}</Words><Company>Acme</Company></Properties>').encode("utf-8")


ACME_ENTRY_ORDER = ["[Content_Types].xml", "_rels/.rels", "word/document.xml", "word/_rels/document.xml.rels",
                    "word/styles.xml", "docProps/core.xml", "docProps/app.xml"]
ACME_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def docx_parts(doc: DocContent, revision: int = 1, last_modified_by: str | None = None) -> dict[str, bytes]:
    return {
        "[Content_Types].xml": _CT, "_rels/.rels": _RELS, "word/document.xml": docx_document_xml(doc),
        "word/_rels/document.xml.rels": _DOC_RELS, "word/styles.xml": _STYLES,
        "docProps/core.xml": docx_core_xml(doc, revision, last_modified_by), "docProps/app.xml": docx_app_xml(doc),
    }


def assemble_acme_docx(parts: dict[str, bytes]) -> bytes:
    """'Acme Office' packaging: fixed entry order, deflate, uniform 1980 timestamps."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in ACME_ENTRY_ORDER:
            zi = zipfile.ZipInfo(name, date_time=ACME_ZIP_TIME)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.create_system = 0
            zf.writestr(zi, parts[name])
    return buf.getvalue()


def render_docx_acme(doc: DocContent) -> bytes:
    return assemble_acme_docx(docx_parts(doc))


# --- registry ----------------------------------------------------------------

@dataclass(frozen=True)
class Generator:
    key: str            # generator id used by the harness (never written to artifacts)
    kind: str           # pdf | jpeg | png | docx
    ext: str

GENERATORS = {
    "pikepdf": Generator("pikepdf", "pdf", "pdf"),
    "plainpdf": Generator("plainpdf", "pdf", "pdf"),
    "acme_camera": Generator("acme_camera", "jpeg", "jpg"),
    "acme_png": Generator("acme_png", "png", "png"),
    "acme_office": Generator("acme_office", "docx", "docx"),
}


def make_content(kind: str, rng: random.Random) -> dict[str, Any]:
    if kind in ("pdf", "docx"):
        return doc_content(rng).to_dict()
    return pixel_spec(rng).to_dict()


def render(generator: str, content: dict[str, Any]) -> bytes:
    g = GENERATORS[generator]
    if g.kind in ("pdf", "docx"):
        doc = DocContent.from_dict(content)
        return {"pikepdf": render_pdf_pikepdf, "plainpdf": render_pdf_plain, "acme_office": render_docx_acme}[generator](doc)
    spec = PixelSpec.from_dict(content)
    return {"acme_camera": render_jpeg_camera, "acme_png": render_png_acme}[generator](spec)
