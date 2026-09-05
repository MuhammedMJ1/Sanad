"""OOXML (docx/xlsx/pptx) container parser: ZIP structure + docProps."""
from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
import zipfile
from typing import Any

CP = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
DC = "http://purl.org/dc/elements/1.1/"
DCTERMS = "http://purl.org/dc/terms/"
EP = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
REL = "http://schemas.openxmlformats.org/package/2006/relationships"
CT = "http://schemas.openxmlformats.org/package/2006/content-types"


def _core(xml: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        return {"_parse_error": str(exc)}
    for el in root:
        tag = el.tag.split("}", 1)[-1]
        out[tag] = (el.text or "").strip()
    return out


def _app(xml: bytes) -> dict[str, str]:
    return _core(xml)


def parse(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"ok": False, "entries": [], "core": {}, "app": {}, "zip_comment": "",
                           "content_types": [], "rels_targets": [], "problems": []}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        out["problems"].append(f"bad zip: {exc}")
        return out
    with zf:
        out["zip_comment"] = zf.comment.decode("utf-8", "replace")
        for zi in zf.infolist():
            out["entries"].append({
                "name": zi.filename, "compress_type": zi.compress_type,
                "date_time": list(zi.date_time), "file_size": zi.file_size,
                "compress_size": zi.compress_size, "extra_len": len(zi.extra),
                "flag_bits": zi.flag_bits, "create_system": zi.create_system,
            })
        names = {e["name"] for e in out["entries"]}
        ts = {tuple(e["date_time"]) for e in out["entries"]}
        out["timestamps_uniform"] = len(ts) == 1
        out["uniform_timestamp"] = list(next(iter(ts))) if len(ts) == 1 else None
        try:
            if "docProps/core.xml" in names:
                out["core"] = _core(zf.read("docProps/core.xml"))
            if "docProps/app.xml" in names:
                out["app"] = _app(zf.read("docProps/app.xml"))
        except (KeyError, RuntimeError) as exc:
            out["problems"].append(f"docProps unreadable: {exc}")
        try:
            ct = ET.fromstring(zf.read("[Content_Types].xml"))
            for ov in ct.iter("{%s}Override" % CT):
                out["content_types"].append(ov.get("PartName", ""))
        except Exception as exc:
            out["problems"].append(f"[Content_Types].xml unreadable: {exc}")
        for rel_name in [n for n in names if n.endswith(".rels")]:
            base = rel_name.rsplit("_rels/", 1)[0]
            try:
                root = ET.fromstring(zf.read(rel_name))
            except Exception as exc:
                out["problems"].append(f"{rel_name} unreadable: {exc}")
                continue
            for r in root.iter("{%s}Relationship" % REL):
                if r.get("TargetMode") == "External":
                    continue
                tgt = r.get("Target", "")
                full = tgt.lstrip("/") if tgt.startswith("/") else (base + tgt)
                full = re.sub(r"[^/]+/\.\./", "", full)
                out["rels_targets"].append({"from": rel_name, "target": full, "exists": full in names})
        out["missing_targets"] = [t["target"] for t in out["rels_targets"] if not t["exists"]]
        out["missing_content_type_parts"] = [p.lstrip("/") for p in out["content_types"] if p.lstrip("/") not in names]
        out["ok"] = True
    return out
