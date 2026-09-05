"""PDF tamper-trace rules (family ``pdf.tamper``).

Every rule reports raw evidence separately from its interpretation and never
treats the mere absence of an optional field as tampering unless the learned
generator profile justifies that expectation empirically.
"""
from __future__ import annotations

from typing import Any

from ..models import Finding, RuleContext
from ..parsers.pdf import parse_xmp
from ..pdfdates import classify_pdf_date, parse_pdf_date, parse_xmp_date, same_instant
from ..structural_profile import confidence_for, generator_key, pdf_features
from . import rule

FAMILY = "pdf.tamper"


def _pdf(ctx: RuleContext) -> dict[str, Any] | None:
    return ctx.parsed.get("pdf")


def _sev_for(n: int) -> tuple[str, float]:
    c = confidence_for(n)
    return ("moderate" if c >= 0.6 else "weak"), c


@rule("pdf.tamper.incremental_revisions", family=FAMILY, formats=["pdf"],
      description="Revision structure and /Prev chain (PDF 32000-1 §7.5.6).")
def incremental_revisions(ctx: RuleContext) -> list[Finding]:
    p = _pdf(ctx)
    if not p:
        return []
    revs = p["revisions"]
    evidence = {
        "revision_count": len(revs),
        "recoverable_count": sum(1 for r in revs if r["recoverable"]),
        "revisions": [
            {k: r[k] for k in ("index", "start_offset", "end_offset", "size_bytes", "startxref",
                               "xref_style", "recoverable", "trailer_prev")}
            for r in revs
        ],
        "trailer_has_prev": p["structure"].get("trailer_has_prev", False),
    }
    if len(revs) > 1:
        return [Finding(
            "pdf.tamper.incremental_revisions", FAMILY, "moderate",
            f"{len(revs)} revisions: file was incrementally saved {len(revs) - 1} time(s) after creation",
            evidence,
            "An incremental update appends a new xref/trailer after %%EOF; each one is a save "
            "that happened after the original document existed. This is evidence of modification, "
            "not of malicious intent by itself — interpret together with the other findings.",
        )]
    return [Finding("pdf.tamper.incremental_revisions", FAMILY, "info",
                    "single revision (no incremental updates present)", evidence,
                    "No earlier revision is physically present. This does not show the file was "
                    "never modified — a full rewrite leaves no prior revision.", is_trace=False)]


@rule("pdf.tamper.recovered_prior_metadata", family=FAMILY, formats=["pdf"],
      description="Superseded /Info, XMP and trailer values recovered from earlier revisions.")
def recovered_prior_metadata(ctx: RuleContext) -> list[Finding]:
    p = _pdf(ctx)
    if not p or len(p["revisions"]) < 2:
        return []
    current_info = p.get("docinfo", {})
    current_xmp = (p.get("xmp") or {}).get("fields", {})
    items: list[dict[str, Any]] = []
    for r in p["revisions"][:-1]:
        if not r["recoverable"]:
            continue
        src = {"revision_index": r["index"], "byte_range": [r["start_offset"], r["end_offset"]],
               "startxref": r["startxref"]}
        for k, old in r["docinfo"].items():
            cur = current_info.get(k)
            if old != cur:
                items.append({"revision": r["index"], "kind": "docinfo", "field": k,
                              "old_value": old, "current_value": cur, "source": src})
        old_xmp = parse_xmp(r["xmp_raw"]).get("fields", {}) if r["xmp_raw"] else {}
        for k, old in old_xmp.items():
            cur = current_xmp.get(k)
            if old != cur:
                items.append({"revision": r["index"], "kind": "xmp", "field": k,
                              "old_value": old, "current_value": cur, "source": src})
    if not items:
        return []
    return [Finding(
        "pdf.tamper.recovered_prior_metadata", FAMILY, "strong",
        f"{len(items)} superseded metadata value(s) physically recoverable from earlier revision(s)",
        {"items": items},
        "The current metadata differs from values still present in an earlier revision of the same "
        "file. The old values are direct evidence of what the document claimed before it was changed.",
    )]


_PAIRS = (
    ("/Author", "dc:creator", "text"),
    ("/Creator", "xmp:CreatorTool", "text"),
    ("/Producer", "pdf:Producer", "text"),
    ("/CreationDate", "xmp:CreateDate", "date"),
    ("/ModDate", "xmp:ModifyDate", "date"),
)


@rule("pdf.tamper.docinfo_xmp_divergence", family=FAMILY, formats=["pdf"],
      description="Logically equivalent DocInfo and XMP fields disagree (dates compared in UTC).")
def docinfo_xmp_divergence(ctx: RuleContext) -> list[Finding]:
    p = _pdf(ctx)
    if not p:
        return []
    info, xmp = p.get("docinfo", {}), (p.get("xmp") or {}).get("fields", {})
    comparisons: list[dict[str, Any]] = []
    for ik, xk, kind in _PAIRS:
        iv, xv = info.get(ik), xmp.get(xk)
        if iv is None or xv is None:
            continue
        rec: dict[str, Any] = {"docinfo_field": ik, "docinfo_value": iv, "xmp_field": xk,
                               "xmp_value": xv, "kind": kind}
        if kind == "date":
            a, b = parse_pdf_date(iv), parse_xmp_date(xv)
            rec["docinfo_utc"] = a.isoformat() if a else None
            rec["xmp_utc"] = b.isoformat() if b else None
            agree = same_instant(a, b)
            rec["agree"] = agree
            rec["formatting_only_difference"] = bool(agree) and iv != xv
        else:
            rec["agree"] = " ".join(iv.split()) == " ".join(xv.split())
        comparisons.append(rec)
    divergent = [c for c in comparisons if c["agree"] is False]
    if not divergent:
        return []
    return [Finding(
        "pdf.tamper.docinfo_xmp_divergence", FAMILY, "moderate",
        f"{len(divergent)} DocInfo/XMP field pair(s) disagree semantically",
        {"comparisons": comparisons},
        "A conforming writer keeps DocInfo and XMP in sync. Semantic disagreement (after "
        "normalising dates to UTC) means one side was changed without the other — typical of "
        "metadata editing or a re-save by a tool that updates only one representation.",
    )]


@rule("pdf.tamper.xmp_identity_anomaly", family=FAMILY, formats=["pdf"],
      description="xmpMM:DocumentID / InstanceID / History consistency.")
def xmp_identity_anomaly(ctx: RuleContext) -> list[Finding]:
    p = _pdf(ctx)
    if not p or not p.get("xmp_raw"):
        return []
    x = p["xmp"]
    fields, hist = x.get("fields", {}), x.get("history", [])
    anomalies: list[dict[str, Any]] = []
    whens = [(ev.get("when"), parse_xmp_date(ev["when"])) for ev in hist if ev.get("when")]
    parsed = [w for _, w in whens if w]
    if len(parsed) >= 2 and any(b < a for a, b in zip(parsed, parsed[1:])):
        anomalies.append({"check": "history_non_monotonic", "history_when": [w for w, _ in whens]})
    if hist and fields.get("xmpMM:InstanceID"):
        last = hist[-1]
        if last.get("instanceID") and last["instanceID"] != fields["xmpMM:InstanceID"]:
            anomalies.append({"check": "last_history_instance_mismatch",
                              "history_instanceID": last["instanceID"],
                              "xmpMM:InstanceID": fields["xmpMM:InstanceID"]})
    md = parse_xmp_date(fields.get("xmp:ModifyDate", "")) if fields.get("xmp:ModifyDate") else None
    if md and parsed and (parsed[-1] - md).total_seconds() > 60:
        anomalies.append({"check": "modify_date_before_last_history_event",
                          "xmp:ModifyDate": fields["xmp:ModifyDate"], "last_history_when": whens[-1][0]})
    # XMP left untouched across an incremental re-save while DocInfo moved on.
    revs = [r for r in p["revisions"] if r["recoverable"]]
    if len(revs) >= 2 and revs[-1]["xmp_raw"] and revs[-1]["xmp_raw"] == revs[0]["xmp_raw"]:
        old_mod, cur_mod = revs[0]["docinfo"].get("/ModDate"), revs[-1]["docinfo"].get("/ModDate")
        if old_mod != cur_mod:
            anomalies.append({"check": "xmp_stale_across_revisions",
                              "xmp_identical_in_revisions": [revs[0]["index"], revs[-1]["index"]],
                              "docinfo_moddate_old": old_mod, "docinfo_moddate_current": cur_mod,
                              "xmpMM:InstanceID": fields.get("xmpMM:InstanceID")})
    if not anomalies:
        return []
    return [Finding(
        "pdf.tamper.xmp_identity_anomaly", FAMILY, "moderate",
        f"{len(anomalies)} XMP identity/history anomaly(ies)",
        {"anomalies": anomalies, "fields": {k: v for k, v in fields.items() if k.startswith("xmpMM")},
         "history_events": hist},
        "XMP media-management data records the save lineage. Non-monotonic history, an InstanceID "
        "that does not match the last recorded save, or XMP that stayed frozen while DocInfo was "
        "updated all indicate a save path that bypassed the XMP-aware writer.",
    )]


@rule("pdf.tamper.structural_fingerprint_conflict", family=FAMILY, formats=["pdf"],
      description="Metadata-independent structure vs the empirically learned profile of the claimed Producer.")
def structural_fingerprint_conflict(ctx: RuleContext) -> list[Finding]:
    p = _pdf(ctx)
    if not p or ctx.profiles is None:
        return []
    gen = generator_key(p.get("docinfo", {}).get("/Producer"))
    feats = pdf_features(p)
    conflicts, n = ctx.profiles.compare("pdf", gen, feats, ignore=(
        "date_dialect_creation", "date_dialect_mod", "id_present", "xmp_present"))
    evidence = {"claimed_producer": p.get("docinfo", {}).get("/Producer"), "generator_key": gen,
                "features": feats, "profile_samples": n, "conflicts": [c.to_dict() for c in conflicts]}
    if n == 0:
        return [Finding("pdf.tamper.structural_fingerprint_conflict", FAMILY, "info",
                        "no empirical structural profile for the claimed producer", evidence,
                        "Without a measured reference corpus for this producer no structural "
                        "comparison is possible; nothing is inferred.", is_trace=False)]
    if not conflicts:
        return []
    sev, conf = _sev_for(n)
    return [Finding(
        "pdf.tamper.structural_fingerprint_conflict", FAMILY, sev,
        f"{len(conflicts)} structural feature(s) never observed for producer '{gen}' (n={n})",
        evidence,
        "The physical layout of the file does not match how the claimed producer was measured to "
        "write files. Either the Producer string was edited or another tool rewrote the file. "
        + ("Corpus is small; treat as supporting evidence only." if conf < 0.6 else ""),
        confidence=conf, is_trace=conf >= 0.35,
    )]


@rule("pdf.tamper.file_id_anomaly", family=FAMILY, formats=["pdf"],
      description="Trailer /ID presence, element relationship and behaviour across revisions.")
def file_id_anomaly(ctx: RuleContext) -> list[Finding]:
    p = _pdf(ctx)
    if not p:
        return []
    cur = p.get("trailer_id")
    revs = [r for r in p["revisions"] if r["recoverable"]]
    raw = {"trailer_id": cur, "per_revision": [{"index": r["index"], "id": r["trailer_id"]} for r in revs]}
    anomalies: list[dict[str, Any]] = []
    conf = 1.0
    gen = generator_key(p.get("docinfo", {}).get("/Producer"))
    if cur is None and ctx.profiles is not None:
        expected, n = ctx.profiles.expected_value("pdf", gen, "id_present")
        if expected == "True" and n >= 2:
            conf = confidence_for(n)
            anomalies.append({"check": "id_absent_but_generator_always_writes_one",
                              "generator_key": gen, "profile_samples": n})
    if cur and len(cur) == 2 and cur[0] == cur[1] and len(p["revisions"]) > 1:
        anomalies.append({"check": "permanent_equals_instance_after_resave"})
    ids = [r["trailer_id"] for r in revs if r["trailer_id"]]
    if len(ids) >= 2:
        if any(a[0] != b[0] for a, b in zip(ids, ids[1:])):
            anomalies.append({"check": "permanent_id_changed_across_revisions",
                              "permanent_ids": [i[0] for i in ids]})
        elif all(a == b for a, b in zip(ids, ids[1:])):
            anomalies.append({"check": "instance_id_not_updated_across_revisions",
                              "instance_ids": [i[1] for i in ids]})
    if not anomalies:
        return []
    strong = any(a["check"] == "permanent_id_changed_across_revisions" for a in anomalies)
    return [Finding(
        "pdf.tamper.file_id_anomaly", FAMILY, "moderate" if strong else "weak",
        f"{len(anomalies)} trailer /ID anomaly(ies)", {"raw": raw, "anomalies": anomalies},
        "/ID[0] is the permanent identifier and must survive re-saves; /ID[1] should change on "
        "every save. Deviations indicate an updater that does not follow the writer's own "
        "conventions. Raw values are listed separately from this reading.",
        confidence=conf, is_trace=conf >= 0.35,
    )]


@rule("pdf.tamper.date_dialect_conflict", family=FAMILY, formats=["pdf"],
      description="Literal PDF date formatting (offset syntax, apostrophes, precision) vs producer habits.")
def date_dialect_conflict(ctx: RuleContext) -> list[Finding]:
    p = _pdf(ctx)
    if not p:
        return []
    info = p.get("docinfo", {})
    cd, md = info.get("/CreationDate"), info.get("/ModDate")
    if not cd and not md:
        return []
    dial = {k: classify_pdf_date(v).to_dict() for k, v in (("/CreationDate", cd), ("/ModDate", md)) if v}
    conflicts: list[dict[str, Any]] = []
    conf = 0.5
    if cd and md:
        a, b = classify_pdf_date(cd), classify_pdf_date(md)
        if a.parsed and b.parsed and a.key != b.key:
            conflicts.append({"check": "two_dialects_within_one_file", "creation": a.key, "modification": b.key})
    gen = generator_key(info.get("/Producer"))
    if ctx.profiles is not None:
        for feat, key in (("date_dialect_creation", "/CreationDate"), ("date_dialect_mod", "/ModDate")):
            if not info.get(key):
                continue
            expected, n = ctx.profiles.expected_value("pdf", gen, feat)
            observed = classify_pdf_date(info[key]).key
            if expected and n >= 2 and expected != observed and expected != "absent":
                conf = max(conf, confidence_for(n))
                conflicts.append({"check": "dialect_differs_from_producer_profile", "field": key,
                                  "observed": observed, "expected": expected, "profile_samples": n})
    if not conflicts:
        return []
    return [Finding(
        "pdf.tamper.date_dialect_conflict", FAMILY, "weak",
        f"{len(conflicts)} date-dialect discrepancy(ies)", {"dialects": dial, "conflicts": conflicts},
        "One producer writes all its dates in one dialect. A second dialect inside the file, or a "
        "dialect the claimed producer was never measured to use, suggests a different tool wrote "
        "that value. Supporting evidence, not standalone proof.",
        confidence=conf,
    )]
