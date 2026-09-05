"""Scan orchestration: intake -> parsers -> rules -> tamper_status -> report dict.

The production report contains only what was obtained from the artifact,
ordinary detector resources (the learned profile store), parser output and
forensic inference. Filenames influence nothing except the ``input`` block.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Any

from . import __version__
from .file_intake import Intake, intake_bytes, intake_file
from .models import AnalysisLimit, RuleContext
from .rules import run_rules
from .signatures import SUPPORTED_FORMATS
from .structural_profile import GeneratorProfiles
from . import tamper_status


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(abs(sum(-c / n * math.log2(c / n) for c in counts.values())), 3)


def generic_characteristics(data: bytes) -> dict[str, Any]:
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return {
        "size_bytes": len(data),
        "shannon_entropy": _entropy(data),
        "printable_ratio": round(printable / len(data), 3) if data else 0.0,
        "head_hex": data[:16].hex(),
        "null_byte_ratio": round(data.count(0) / len(data), 3) if data else 0.0,
    }


def _parse(intake: Intake, ctx: RuleContext) -> list[str]:
    fmt = intake.detected_format
    used: list[str] = []
    if fmt == "pdf":
        from .parsers import pdf as pdf_parser
        try:
            ctx.parsed["pdf"] = pdf_parser.parse(intake.data)
            used.append("pdf")
            if ctx.parsed["pdf"].get("error"):
                ctx.limit("pdf.structure", f"pikepdf could not fully open the document: {ctx.parsed['pdf']['error']}")
        except Exception as exc:
            ctx.limit("pdf", f"parser failed: {type(exc).__name__}: {exc}")
    elif fmt in ("jpeg", "png"):
        from .parsers import image as image_parser
        try:
            ctx.parsed["image"] = image_parser.parse(intake.data, fmt)
            used.append("image")
            if not ctx.parsed["image"].get("decodable"):
                ctx.limit("image.pixels", "image data could not be decoded; pixel-level checks skipped")
        except Exception as exc:
            ctx.limit("image", f"parser failed: {type(exc).__name__}: {exc}")
    elif fmt in ("docx", "xlsx", "pptx"):
        from .parsers import ooxml as ooxml_parser
        try:
            ctx.parsed["ooxml"] = ooxml_parser.parse(intake.data)
            used.append("ooxml")
            if not ctx.parsed["ooxml"].get("ok"):
                ctx.limit("ooxml", "container not readable: " + "; ".join(ctx.parsed["ooxml"].get("problems", [])))
        except Exception as exc:
            ctx.limit("ooxml", f"parser failed: {type(exc).__name__}: {exc}")
    elif fmt == "zip":
        from .parsers import ooxml as ooxml_parser
        ctx.parsed["ooxml"] = ooxml_parser.parse(intake.data)
        used.append("zip")
        ctx.limit("ooxml.tamper", "ZIP container is not an OOXML package; only generic container "
                                  "structure was read")
    elif fmt == "empty":
        ctx.limit("all", "zero-byte input: nothing to analyse")
    else:
        ctx.limit("unsupported_format", "no recognised signature; only safe generic characteristics "
                                        "were computed")
    return used


def _details(ctx: RuleContext) -> dict[str, Any]:
    d: dict[str, Any] = {}
    if "pdf" in ctx.parsed:
        p = ctx.parsed["pdf"]
        d["pdf"] = {
            "docinfo": p.get("docinfo"), "xmp_fields": (p.get("xmp") or {}).get("fields"),
            "xmp_history": (p.get("xmp") or {}).get("history"), "trailer_id": p.get("trailer_id"),
            "structure": p.get("structure"), "page_count": p.get("page_count"),
            "revisions": [{k: v for k, v in r.items() if k not in ("xmp_raw",)} for r in p.get("revisions", [])],
        }
    if "image" in ctx.parsed:
        i = ctx.parsed["image"]
        d["image"] = {k: i.get(k) for k in ("format", "width", "height", "pixel_size", "mode", "app_segments",
                                              "dqt_tables", "subsampling", "progressive", "thumbnail",
                                              "makernote", "chunks", "text_chunks", "time", "problems")}
        ex = i.get("exif")
        if ex:
            d["image"]["exif"] = {k: ex.get(k) for k in ("endian", "ifd0", "exif", "ifd1", "problems")}
    if "ooxml" in ctx.parsed:
        o = ctx.parsed["ooxml"]
        d["ooxml"] = {k: o.get(k) for k in ("entries", "core", "app", "zip_comment", "content_types",
                                              "missing_targets", "missing_content_type_parts", "problems")}
    return d


def scan_intake(intake: Intake, profiles: GeneratorProfiles | None = None) -> dict[str, Any]:
    profiles = profiles if profiles is not None else GeneratorProfiles.load()
    ctx = RuleContext(data=intake.data, detected_format=intake.detected_format, profiles=profiles)
    parsers = _parse(intake, ctx)
    findings = run_rules(ctx) if intake.detected_format in SUPPORTED_FORMATS else []
    status = tamper_status.compute(intake.detected_format, ctx.parsed, findings)
    sig = intake.signature
    return {
        "docforensics_version": __version__,
        "input": {
            "path": intake.path, "name": intake.name, "size_bytes": intake.size_bytes,
            "sha256": intake.sha256, "detected_format": sig.detected_format,
            "format_family": sig.family, "format_evidence": sig.magic,
            "format_identification": "content-first (magic bytes / container inspection)",
            "extension_hint": intake.extension, "extension_agrees_with_content": intake.extension_agrees,
            "supported": sig.detected_format in SUPPORTED_FORMATS,
        },
        "parsers": parsers,
        "generic": generic_characteristics(intake.data),
        "findings": [f.to_dict() for f in findings],
        "analysis_limits": [l.to_dict() for l in ctx.limits],
        "tamper_status": status,
        "details": _details(ctx),
        "profile_store": {"source": profiles.source, "loaded": bool(profiles.store)},
    }


def scan_bytes(data: bytes, name: str = "<bytes>", profiles: GeneratorProfiles | None = None) -> dict[str, Any]:
    return scan_intake(intake_bytes(data, name=name), profiles)


def scan_file(path: str, profiles: GeneratorProfiles | None = None) -> dict[str, Any]:
    return scan_intake(intake_file(path), profiles)
