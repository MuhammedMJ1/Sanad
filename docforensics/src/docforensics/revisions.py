"""PDF revision recovery (PDF 32000-1:2008 §7.5.6 incremental updates).

An incrementally updated PDF keeps every earlier revision physically intact:
each save appends new objects, a new xref section and a trailer whose /Prev
points at the previous xref. Truncating the file at an earlier ``%%EOF``
therefore yields the earlier document, and superseded /Info, XMP and /ID
values remain recoverable. This module finds the revision boundaries by
scanning for ``startxref ... %%EOF`` and opens each prefix with pikepdf.
"""
from __future__ import annotations

import io
import re
from dataclasses import dataclass, field, asdict
from typing import Any

_EOF_RE = re.compile(rb"startxref\s+(\d+)\s*%%EOF[ \t]*(?:\r\n|\r|\n)?")


@dataclass
class Revision:
    index: int
    start_offset: int
    end_offset: int
    startxref: int | None
    xref_style: str = "unknown"          # table | stream | unknown
    recoverable: bool = False
    docinfo: dict[str, str] = field(default_factory=dict)
    xmp_raw: str | None = None
    trailer_id: list[str] | None = None
    trailer_prev: int | None = None
    error: str | None = None

    @property
    def size_bytes(self) -> int:
        return self.end_offset - self.start_offset

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["size_bytes"] = self.size_bytes
        return d


def _xref_style_at(data: bytes, offset: int | None) -> str:
    if offset is None or offset < 0 or offset >= len(data):
        return "unknown"
    window = data[offset:offset + 200].lstrip()
    if window.startswith(b"xref"):
        return "table"
    if re.match(rb"\d+\s+\d+\s+obj", window):
        return "stream"
    return "unknown"


def find_revisions(data: bytes) -> list[Revision]:
    revs: list[Revision] = []
    start = 0
    for i, m in enumerate(_EOF_RE.finditer(data)):
        sx = int(m.group(1))
        revs.append(Revision(index=i, start_offset=start, end_offset=m.end(),
                             startxref=sx, xref_style=_xref_style_at(data, sx)))
        start = m.end()
    if not revs:
        revs.append(Revision(index=0, start_offset=0, end_offset=len(data), startxref=None))
    return revs


def _docinfo_of(pdf: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        info = pdf.docinfo
    except Exception:
        return out
    for k, v in info.items():
        try:
            out[str(k)] = str(v)
        except Exception:
            out[str(k)] = repr(v)
    return out


def _xmp_of(pdf: Any) -> str | None:
    try:
        meta = pdf.Root.get("/Metadata")
        if meta is None:
            return None
        return bytes(meta.read_bytes()).decode("utf-8", "replace")
    except Exception:
        return None


def _id_of(pdf: Any) -> list[str] | None:
    try:
        ids = pdf.trailer.get("/ID")
        if ids is None:
            return None
        return [bytes(x).hex() for x in ids]
    except Exception:
        return None


def open_revision(data: bytes, rev: Revision) -> Any | None:
    """Open the document as it existed at ``rev`` (None if unrecoverable)."""
    import pikepdf
    try:
        return pikepdf.open(io.BytesIO(data[:rev.end_offset]))
    except Exception:
        return None


def recover(data: bytes, revs: list[Revision]) -> list[Revision]:
    """Fill each revision with the metadata physically recoverable from it."""
    for rev in revs:
        pdf = open_revision(data, rev)
        if pdf is None:
            rev.error = "prefix not parseable"
            continue
        with pdf:
            rev.recoverable = True
            rev.docinfo = _docinfo_of(pdf)
            rev.xmp_raw = _xmp_of(pdf)
            rev.trailer_id = _id_of(pdf)
            try:
                prev = pdf.trailer.get("/Prev")
                rev.trailer_prev = int(prev) if prev is not None else None
            except Exception:
                rev.trailer_prev = None
    return revs
