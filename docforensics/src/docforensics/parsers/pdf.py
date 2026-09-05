"""PDF parser: structure, DocInfo, XMP, trailer /ID and recoverable revisions."""
from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
from typing import Any

from ..revisions import find_revisions, recover

NS = {
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "dc": "http://purl.org/dc/elements/1.1/",
    "xmp": "http://ns.adobe.com/xap/1.0/",
    "xmpMM": "http://ns.adobe.com/xap/1.0/mm/",
    "stEvt": "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#",
    "pdf": "http://ns.adobe.com/pdf/1.3/",
}


def _q(prefix: str, local: str) -> str:
    return "{%s}%s" % (NS[prefix], local)


def _text_or_attr(desc: ET.Element, prefix: str, local: str) -> str | None:
    val = desc.get(_q(prefix, local))
    if val is not None:
        return val
    el = desc.find(_q(prefix, local))
    if el is None:
        return None
    # dc:creator is rdf:Seq/rdf:li ; xmp:* may be rdf:Alt
    li = el.find(".//" + _q("rdf", "li"))
    if li is not None and li.text is not None:
        return li.text.strip()
    return (el.text or "").strip() or None


def parse_xmp(raw: str | None) -> dict[str, Any]:
    out: dict[str, Any] = {"present": bool(raw), "fields": {}, "history": [], "parse_error": None}
    if not raw:
        return out
    start = raw.find("<x:xmpmeta")
    end = raw.rfind("</x:xmpmeta>")
    text = raw[start:end + len("</x:xmpmeta>")] if start != -1 and end != -1 else raw
    try:
        root = ET.fromstring(text.encode("utf-8"))
    except ET.ParseError as exc:
        out["parse_error"] = str(exc)
        return out
    fields: dict[str, str] = {}
    for desc in root.iter(_q("rdf", "Description")):
        for prefix, local in (("dc", "creator"), ("dc", "title"), ("xmp", "CreatorTool"),
                              ("xmp", "CreateDate"), ("xmp", "ModifyDate"), ("xmp", "MetadataDate"),
                              ("pdf", "Producer"), ("xmpMM", "DocumentID"), ("xmpMM", "InstanceID"),
                              ("xmpMM", "OriginalDocumentID")):
            v = _text_or_attr(desc, prefix, local)
            if v is not None and f"{prefix}:{local}" not in fields:
                fields[f"{prefix}:{local}"] = v
        hist = desc.find(_q("xmpMM", "History"))
        if hist is not None:
            for li in hist.iter(_q("rdf", "li")):
                ev = {}
                for local in ("action", "when", "instanceID", "softwareAgent", "changed", "parameters"):
                    v = li.get(_q("stEvt", local))
                    if v is None:
                        el = li.find(_q("stEvt", local))
                        v = (el.text or "").strip() if el is not None else None
                    if v:
                        ev[local] = v
                if ev:
                    out["history"].append(ev)
    out["fields"] = fields
    return out


_OBJ_RE = re.compile(rb"(?m)^\s*(\d+)\s+(\d+)\s+obj\b")
_FILTER_RE = re.compile(rb"/Filter\s*(?:/(\w+)|\[([^\]]*)\])")
_STREAM_RE = re.compile(rb"\bstream\r?\n")


def _structure(data: bytes, revs: list[Any]) -> dict[str, Any]:
    head = data[:64]
    version = None
    m = re.match(rb"%PDF-(\d\.\d)", head)
    if m:
        version = m.group(1).decode()
    lines = data[:256].split(b"\n", 3)
    binary_comment = len(lines) > 1 and lines[1].startswith(b"%") and any(b > 127 for b in lines[1][:8])
    objnums = sorted({int(x[0]) for x in _OBJ_RE.findall(data)})
    max_obj = objnums[-1] if objnums else 0
    gaps = (max_obj - len(objnums)) if objnums else 0
    filters: set[str] = set()
    for a, b in _FILTER_RE.findall(data):
        if a:
            filters.add(a.decode("latin-1"))
        else:
            filters.update(x.decode("latin-1") for x in re.findall(rb"/(\w+)", b))
    return {
        "version": version,
        "binary_comment": bool(binary_comment),
        "object_count": len(objnums),
        "max_object_number": max_obj,
        "object_number_gaps": gaps,
        "gap_ratio": round(gaps / max_obj, 3) if max_obj else 0.0,
        "stream_count": len(_STREAM_RE.findall(data)),
        "filters": sorted(filters),
        "has_objstm": b"/ObjStm" in data,
        "has_xref_stream": b"/Type /XRef" in data or b"/Type/XRef" in data,
        "linearized": b"/Linearized" in data[:2048],
        "xref_styles": [r.xref_style for r in revs],
        "trailer_has_prev": b"/Prev" in data,
        "startxref_count": len(revs) if revs and revs[0].startxref is not None else 0,
    }


def parse(data: bytes) -> dict[str, Any]:
    import pikepdf

    out: dict[str, Any] = {"ok": False, "error": None}
    revs = find_revisions(data)
    revs = recover(data, revs)
    out["revisions"] = [r.to_dict() for r in revs]
    out["revision_count"] = len(revs)
    out["structure"] = _structure(data, revs)
    try:
        pdf = pikepdf.open(io.BytesIO(data))
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        # still expose what the last recoverable revision told us
        last = revs[-1]
        out["docinfo"] = dict(last.docinfo)
        out["xmp_raw"] = last.xmp_raw
        out["trailer_id"] = last.trailer_id
        out["xmp"] = parse_xmp(last.xmp_raw)
        return out
    with pdf:
        out["ok"] = True
        out["docinfo"] = {str(k): str(v) for k, v in pdf.docinfo.items()}
        meta = pdf.Root.get("/Metadata")
        out["xmp_raw"] = bytes(meta.read_bytes()).decode("utf-8", "replace") if meta is not None else None
        ids = pdf.trailer.get("/ID")
        out["trailer_id"] = [bytes(x).hex() for x in ids] if ids is not None else None
        out["page_count"] = len(pdf.pages)
        layouts = []
        for page in pdf.pages:
            c = page.obj.get("/Contents")
            if c is None:
                layouts.append("none")
            elif isinstance(c, pikepdf.Array):
                layouts.append("array")
            else:
                layouts.append("single")
        out["structure"]["content_stream_layout"] = ",".join(sorted(set(layouts))) or "none"
        out["structure"]["pdf_version_catalog"] = str(pdf.Root.get("/Version", "")) or None
    out["xmp"] = parse_xmp(out["xmp_raw"])
    return out
