"""Content-first format identification.

The filename suffix is never trusted for identification; it is recorded only
as a supplemental hint so the report can say "content is PDF, extension said
.jpg". Detection order: exact magic bytes, then container inspection.
"""
from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass

PNG_SIG = b"\x89PNG\r\n\x1a\n"

# Extensions we would *expect* for each detected format (supplemental only).
EXPECTED_EXTENSIONS = {
    "pdf": {".pdf"},
    "jpeg": {".jpg", ".jpeg", ".jpe"},
    "png": {".png"},
    "docx": {".docx", ".docm", ".dotx"},
    "xlsx": {".xlsx", ".xlsm", ".xltx"},
    "pptx": {".pptx", ".pptm", ".potx"},
    "zip": {".zip"},
}

SUPPORTED_FORMATS = {"pdf", "jpeg", "png", "docx", "xlsx", "pptx"}
PARTIAL_FORMATS = {"zip"}  # container readable, no format-specific forensics


@dataclass(frozen=True)
class Signature:
    detected_format: str          # pdf|jpeg|png|docx|xlsx|pptx|zip|empty|unknown
    family: str                   # pdf|image|ooxml|archive|none
    magic: str                    # human-readable description of the evidence
    header_offset: int = 0        # where the signature was found (PDF may have junk)


def _ooxml_kind(data: bytes) -> str | None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            if "[Content_Types].xml" not in names:
                return None
            ct = zf.read("[Content_Types].xml").decode("utf-8", "replace")
    except (zipfile.BadZipFile, KeyError, RuntimeError, OSError):
        return None
    if "wordprocessingml.document.main" in ct or any(n.startswith("word/") for n in names):
        return "docx"
    if "spreadsheetml.sheet.main" in ct or any(n.startswith("xl/") for n in names):
        return "xlsx"
    if "presentationml.presentation.main" in ct or any(n.startswith("ppt/") for n in names):
        return "pptx"
    return None


def identify(data: bytes) -> Signature:
    """Identify ``data`` from its bytes alone."""
    if not data:
        return Signature("empty", "none", "zero-byte input")
    head = data[:1024]
    idx = head.find(b"%PDF-")
    if idx != -1:
        return Signature("pdf", "pdf", "%PDF- header", idx)
    if data[:3] == b"\xff\xd8\xff":
        return Signature("jpeg", "image", "JPEG SOI + marker")
    if data[:8] == PNG_SIG:
        return Signature("png", "image", "PNG 8-byte signature")
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        kind = _ooxml_kind(data)
        if kind:
            return Signature(kind, "ooxml", "ZIP container with OOXML [Content_Types].xml")
        return Signature("zip", "archive", "ZIP local-file header")
    return Signature("unknown", "none", "no recognised signature")


def extension_hint(name: str | None) -> str | None:
    """Lower-cased suffix of ``name`` or None (supplemental evidence only)."""
    if not name:
        return None
    dot = name.rfind(".")
    if dot <= 0 or dot == len(name) - 1:
        return None
    return name[dot:].lower()
