"""Metadata-independent structural fingerprints + empirically learned profiles.

A *feature vector* describes how a file is physically laid out (xref style,
object streams, filters, chunk order, ZIP entry order, ...), never what its
metadata claims. A *generator profile* is the multiset of feature values
observed for one claimed generator across a controlled reference corpus.
Nothing here is hard-coded: ``generators.json`` is produced by
``docforensics-fixtures learn-profiles`` and ships as an ordinary static
detector resource. When a generator has too few samples the comparison
reports low confidence instead of pretending to be conclusive.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .pdfdates import classify_pdf_date

DEFAULT_PROFILE_PATH = Path(__file__).parent / "profiles" / "generators.json"


def generator_key(name: str | None) -> str | None:
    """Normalise a Producer / Software / Application string to a family key."""
    if not name:
        return None
    m = re.match(r"\s*([A-Za-z][A-Za-z0-9_+.-]*)", name)
    if not m:
        return None
    return m.group(1).lower().rstrip(".")


# --- feature extraction -----------------------------------------------------

def pdf_features(parsed: dict[str, Any]) -> dict[str, str]:
    st = parsed.get("structure", {})
    info = parsed.get("docinfo", {})
    styles = [s for s in st.get("xref_styles", []) if s != "unknown"]
    feats = {
        "xref_style_first": styles[0] if styles else "unknown",
        "has_objstm": str(st.get("has_objstm", False)),
        "binary_comment": str(st.get("binary_comment", False)),
        "linearized": str(st.get("linearized", False)),
        "filters": "+".join(st.get("filters", [])) or "none",
        "header_version": str(st.get("version")),
        "content_stream_layout": str(st.get("content_stream_layout", "unknown")),
        "id_present": str(parsed.get("trailer_id") is not None),
        "xmp_present": str(bool(parsed.get("xmp_raw"))),
    }
    for key, field in (("date_dialect_creation", "/CreationDate"), ("date_dialect_mod", "/ModDate")):
        v = info.get(field)
        feats[key] = classify_pdf_date(v).key if v else "absent"
    return feats


def jpeg_features(parsed: dict[str, Any]) -> dict[str, str]:
    return {
        "app_segment_order": ">".join(parsed.get("app_segment_order", [])) or "none",
        "dqt_hash": str(parsed.get("dqt_hash")),
        "subsampling": str(parsed.get("subsampling")),
        "progressive": str(parsed.get("progressive", False)),
        "exif_present": str(bool(parsed.get("exif"))),
        "thumbnail_present": str(parsed.get("thumbnail", {}).get("present", False)),
        "makernote_present": str(parsed.get("makernote", {}).get("present", False)),
    }


def png_features(parsed: dict[str, Any]) -> dict[str, str]:
    return {
        "chunk_order": ">".join(parsed.get("chunk_order", [])) or "none",
        "has_time": str("tIME" in parsed.get("chunk_order", [])),
        "bit_depth_color": f"{parsed.get('bit_depth')}/{parsed.get('color_type')}",
    }


def ooxml_features(parsed: dict[str, Any]) -> dict[str, str]:
    entries = parsed.get("entries", [])
    return {
        "entry_order": ">".join(e["name"] for e in entries) or "none",
        "compression_methods": "+".join(sorted({str(e["compress_type"]) for e in entries})) or "none",
        "timestamps_uniform": str(parsed.get("timestamps_uniform", False)),
        "uniform_timestamp": str(parsed.get("uniform_timestamp")),
        "has_app_xml": str(bool(parsed.get("app"))),
        "has_core_xml": str(bool(parsed.get("core"))),
        "zip_comment": str(bool(parsed.get("zip_comment"))),
    }


# --- profile store ----------------------------------------------------------

def confidence_for(n: int) -> float:
    if n >= 20:
        return 0.9
    if n >= 5:
        return 0.6
    if n >= 2:
        return 0.35
    return 0.15


@dataclass
class Conflict:
    feature: str
    observed: str
    expected: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"feature": self.feature, "observed": self.observed, "expected": self.expected}


class GeneratorProfiles:
    """{kind: {generator_key: {"n": int, "features": {feature: {value: count}}}}}"""

    def __init__(self, store: dict[str, Any] | None = None, source: str | None = None):
        self.store: dict[str, Any] = store or {}
        self.source = source

    @classmethod
    def load(cls, path: Path | None = None) -> "GeneratorProfiles":
        p = path or DEFAULT_PROFILE_PATH
        if not p.exists():
            return cls({}, None)
        with open(p, "r", encoding="utf-8") as fh:
            return cls(json.load(fh), str(p))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.store, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    def learn(self, kind: str, gen: str, feats: dict[str, str]) -> None:
        g = self.store.setdefault(kind, {}).setdefault(gen, {"n": 0, "features": {}})
        g["n"] += 1
        for k, v in feats.items():
            g["features"].setdefault(k, {})
            g["features"][k][v] = g["features"][k].get(v, 0) + 1

    def sample_count(self, kind: str, gen: str | None) -> int:
        if gen is None:
            return 0
        return int(self.store.get(kind, {}).get(gen, {}).get("n", 0))

    def known_generators(self, kind: str) -> list[str]:
        return sorted(self.store.get(kind, {}).keys())

    def compare(self, kind: str, gen: str | None, feats: dict[str, str],
                ignore: tuple[str, ...] = ()) -> tuple[list[Conflict], int]:
        """Features whose observed value was never seen for ``gen``."""
        n = self.sample_count(kind, gen)
        if n == 0:
            return [], 0
        prof = self.store[kind][gen]["features"]  # type: ignore[index]
        conflicts: list[Conflict] = []
        for k, v in feats.items():
            if k in ignore or k not in prof:
                continue
            if v not in prof[k]:
                conflicts.append(Conflict(k, v, sorted(prof[k].keys())))
        return conflicts, n

    def expected_value(self, kind: str, gen: str | None, feature: str) -> tuple[str | None, int]:
        """The single value always observed for ``feature`` (None if it varies)."""
        n = self.sample_count(kind, gen)
        if n == 0:
            return None, 0
        vals = self.store[kind][gen]["features"].get(feature, {})  # type: ignore[index]
        if len(vals) == 1:
            return next(iter(vals)), n
        return None, n
