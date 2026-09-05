"""OOXML (docx/xlsx/pptx) tamper-trace rules (family ``ooxml.tamper``)."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any

from ..models import Finding, RuleContext
from ..pdfdates import parse_xmp_date
from ..structural_profile import confidence_for, generator_key, ooxml_features
from . import rule

FAMILY = "ooxml.tamper"
FORMATS = ["docx", "xlsx", "pptx"]


def _ox(ctx: RuleContext) -> dict[str, Any] | None:
    o = ctx.parsed.get("ooxml")
    return o if o and o.get("ok") else None


def _app_key(o: dict[str, Any]) -> str | None:
    return generator_key((o.get("app") or {}).get("Application"))


@rule("ooxml.tamper.core_dates_anomaly", family=FAMILY, formats=FORMATS,
      description="dcterms:modified earlier than dcterms:created.")
def core_dates_anomaly(ctx: RuleContext) -> list[Finding]:
    o = _ox(ctx)
    if not o:
        return []
    c, m = o["core"].get("created"), o["core"].get("modified")
    a, b = parse_xmp_date(c or ""), parse_xmp_date(m or "")
    if a and b and b < a:
        return [Finding("ooxml.tamper.core_dates_anomaly", FAMILY, "strong",
                        "docProps/core.xml: modified precedes created",
                        {"created": c, "modified": m},
                        "A package cannot be modified before it was created; a date was rewritten.")]
    return []


@rule("ooxml.tamper.entry_timestamp_vs_core_modified", family=FAMILY, formats=FORMATS,
      description="ZIP entry timestamps later than the declared dcterms:modified.")
def entry_timestamp_vs_core_modified(ctx: RuleContext) -> list[Finding]:
    o = _ox(ctx)
    if not o:
        return []
    m = parse_xmp_date(o["core"].get("modified") or "")
    if not m:
        return []
    late = []
    for e in o["entries"]:
        try:
            ts = datetime(*e["date_time"], tzinfo=timezone.utc)
        except (TypeError, ValueError):
            continue
        # ZIP times are local with unknown zone: only flag beyond the widest offset.
        if ts - m > timedelta(hours=15):
            late.append({"name": e["name"], "date_time": e["date_time"]})
    if not late:
        return []
    return [Finding("ooxml.tamper.entry_timestamp_vs_core_modified", FAMILY, "moderate",
                    f"{len(late)} package part(s) written after the declared modification time",
                    {"modified": o["core"].get("modified"), "late_entries": late},
                    "The container was rebuilt after the date the document claims it was last "
                    "modified (even allowing any timezone for the ZIP timestamps).")]


@rule("ooxml.tamper.package_profile_conflict", family=FAMILY, formats=FORMATS,
      description="ZIP entry order / compression / timestamps vs the learned profile of the claimed Application.")
def package_profile_conflict(ctx: RuleContext) -> list[Finding]:
    o = _ox(ctx)
    if not o or ctx.profiles is None:
        return []
    gen = _app_key(o)
    feats = ooxml_features(o)
    conflicts, n = ctx.profiles.compare("ooxml", gen, feats)
    if n == 0 or not conflicts:
        return []
    conf = confidence_for(n)
    return [Finding("ooxml.tamper.package_profile_conflict", FAMILY, "moderate" if conf >= 0.6 else "weak",
                    f"{len(conflicts)} package feature(s) never observed for application '{gen}' (n={n})",
                    {"claimed_application": gen, "features": feats, "profile_samples": n,
                     "conflicts": [c.to_dict() for c in conflicts]},
                    "The application named in app.xml writes its ZIP container in a fixed way "
                    "(entry order, compression, uniform timestamps). A different layout means the "
                    "package was re-zipped by another tool after that application saved it.",
                    confidence=conf, is_trace=conf >= 0.35)]


@rule("ooxml.tamper.revision_counter_anomaly", family=FAMILY, formats=FORMATS,
      description="cp:revision vs the created/modified span.")
def revision_counter_anomaly(ctx: RuleContext) -> list[Finding]:
    o = _ox(ctx)
    if not o:
        return []
    rev = o["core"].get("revision")
    if rev is None or rev == "":
        return []
    if not rev.isdigit():
        return [Finding("ooxml.tamper.revision_counter_anomaly", FAMILY, "info",
                        f"non-numeric revision counter: {rev!r}", {"revision": rev}, "", is_trace=False)]
    a, b = parse_xmp_date(o["core"].get("created") or ""), parse_xmp_date(o["core"].get("modified") or "")
    if int(rev) == 1 and a and b and (b - a).total_seconds() > 60:
        return [Finding("ooxml.tamper.revision_counter_anomaly", FAMILY, "weak",
                        "revision counter is 1 although the document was modified after creation",
                        {"revision": rev, "created": o["core"].get("created"), "modified": o["core"].get("modified")},
                        "Office increments cp:revision on every save; a counter stuck at 1 across a "
                        "created/modified gap points at an editor that does not maintain it.")]
    return []


@rule("ooxml.tamper.relationship_inconsistency", family=FAMILY, formats=FORMATS,
      description="[Content_Types] overrides and relationship targets must resolve to real parts.")
def relationship_inconsistency(ctx: RuleContext) -> list[Finding]:
    o = _ox(ctx)
    if not o:
        return []
    missing = o.get("missing_targets", []) + o.get("missing_content_type_parts", [])
    if not missing:
        return []
    return [Finding("ooxml.tamper.relationship_inconsistency", FAMILY, "moderate",
                    f"{len(missing)} declared part(s) missing from the package", {"missing": sorted(set(missing))},
                    "Office never writes dangling relationships; parts were removed or the package "
                    "was assembled by hand.")]


@rule("ooxml.tamper.last_modified_by_anomaly", family=FAMILY, formats=FORMATS,
      description="lastModifiedBy vs creator and the created/modified span.")
def last_modified_by_anomaly(ctx: RuleContext) -> list[Finding]:
    o = _ox(ctx)
    if not o:
        return []
    c = o["core"]
    lmb, creator = c.get("lastModifiedBy"), c.get("creator")
    a, b = parse_xmp_date(c.get("created") or ""), parse_xmp_date(c.get("modified") or "")
    if lmb and creator and lmb != creator and a and b and abs((b - a).total_seconds()) < 1:
        return [Finding("ooxml.tamper.last_modified_by_anomaly", FAMILY, "weak",
                        "lastModifiedBy differs from creator but modified == created",
                        {"creator": creator, "lastModifiedBy": lmb, "created": c.get("created"),
                         "modified": c.get("modified")},
                        "A second author cannot have saved the file at the very instant it was "
                        "created; one of these properties was edited.")]
    return []


@rule("ooxml.tamper.zip_comment_present", family=FAMILY, formats=FORMATS,
      description="Archive comment present (Office never writes one).", detects_trace=False)
def zip_comment_present(ctx: RuleContext) -> list[Finding]:
    o = _ox(ctx)
    if not o or not o.get("zip_comment"):
        return []
    return [Finding("ooxml.tamper.zip_comment_present", FAMILY, "info", "ZIP archive comment present",
                    {"comment_length": len(o["zip_comment"])}, "", is_trace=False)]
