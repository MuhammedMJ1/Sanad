# Sterile memory: knowledge that compounds and provably cannot rot.
#
# Every memory system eventually poisons itself: it stores right and wrong
# conclusions alike, and stale "facts" outlive the code they described. This
# store is different in two mechanical ways:
#
#   ADMISSION — an insight enters ONLY if the hallucination gate (factcheck)
#   can back every checkable claim in it against the deterministic graph.
#   Refuted or unresolvable claims mean rejection, with the gate report as
#   the reason. No claim, no entry.
#
#   RE-STERILIZATION — `reverify()` re-judges every stored entry against the
#   CURRENT graph. An entry whose claims no longer hold (code changed, symbol
#   vanished) is quarantined as `stale` with the failing verdict attached —
#   auditable, never silently kept as truth, never silently deleted.
#
# So the graph accumulates verified experience with every investigation:
# a small model sitting on a mature memory knows things about THIS repo that
# no frontier model knows cold — and none of it can be a hallucination.
from __future__ import annotations

import json
import time
from pathlib import Path

import networkx as nx

from graphify.factcheck import (
    REFUTED,
    UNKNOWN,
    VERIFIED,
    VERIFIED_INDIRECT,
    Verdict,
    check_claims,
    extract_claims,
)

MEMORY_FILENAME = ".graphify_memory.json"

MAX_INSIGHT_CHARS = 1200
MAX_RECALL = 8

ADMITTED = "ADMITTED"
REJECTED = "REJECTED"

STATUS_ACTIVE = "active"
STATUS_STALE = "stale"

_SUPPORTED = (VERIFIED, VERIFIED_INDIRECT)


def load_memory(out_dir: Path) -> dict:
    p = Path(out_dir) / MEMORY_FILENAME
    if not p.exists():
        return {"version": 1, "next_id": 1, "entries": []}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": 1, "next_id": 1, "entries": []}
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        return {"version": 1, "next_id": 1, "entries": []}
    data.setdefault("next_id", len(data["entries"]) + 1)
    return data


def save_memory(out_dir: Path, data: dict) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    p = out / MEMORY_FILENAME
    p.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return p


def _claims_payload(verdicts: list[Verdict]) -> list[dict]:
    return [
        {
            "subject": v.claim.subject,
            "relation": v.claim.relation,
            "object": v.claim.object,
            "verdict": v.verdict,
            "evidence": v.evidence,
        }
        for v in verdicts
    ]


def _anchors(verdicts: list[Verdict]) -> list[str]:
    """Node labels the verified claims touched — the recall keys."""
    seen: list[str] = []
    for v in verdicts:
        if v.verdict not in _SUPPORTED:
            continue
        for label in [v.claim.subject, v.claim.object, *v.path]:
            label = str(label).strip()
            if label and label not in seen:
                seen.append(label)
    return seen


def admit(
    G: nx.Graph,
    data: dict,
    insight: str,
    *,
    source: str = "manual",
    question: str = "",
    now: float | None = None,
) -> tuple[str, dict | None, list[Verdict]]:
    """Try to admit an insight. Returns (ADMITTED|REJECTED, entry|None, verdicts).

    Sterility rule: at least one checkable claim, and EVERY claim supported
    (VERIFIED or VERIFIED_INDIRECT). A refuted claim is a lie and an unknown
    claim is unprovable — neither may enter permanent memory.
    """
    insight = " ".join(insight.split())[:MAX_INSIGHT_CHARS]
    if not insight:
        return REJECTED, None, []
    claims = extract_claims(insight)
    if not claims:
        return REJECTED, None, []
    verdicts = check_claims(G, claims)
    if any(v.verdict in (REFUTED, UNKNOWN) for v in verdicts):
        return REJECTED, None, verdicts

    entry = {
        "id": f"m{data.get('next_id', 1)}",
        "insight": insight,
        "question": question,
        "source": source,
        "created_at": round(now if now is not None else time.time()),
        "status": STATUS_ACTIVE,
        "confirmations": 1,
        "stale_reason": "",
        "anchors": _anchors(verdicts),
        "claims": _claims_payload(verdicts),
    }
    data["next_id"] = int(data.get("next_id", 1)) + 1
    data.setdefault("entries", []).append(entry)
    return ADMITTED, entry, verdicts


def forget(data: dict, entry_id: str) -> bool:
    entries = data.get("entries", [])
    keep = [e for e in entries if e.get("id") != entry_id]
    if len(keep) == len(entries):
        return False
    data["entries"] = keep
    return True


def recall(data: dict, query: str, *, include_stale: bool = False) -> list[dict]:
    """Rank entries by anchor/insight token overlap with the query."""
    qtokens = {t for t in query.lower().replace("`", " ").split() if t}
    if not qtokens:
        return []
    scored: list[tuple[float, dict]] = []
    for e in data.get("entries", []):
        if not include_stale and e.get("status") != STATUS_ACTIVE:
            continue
        anchor_text = " ".join(e.get("anchors", [])).lower()
        insight_text = str(e.get("insight", "")).lower()
        score = 0.0
        for t in qtokens:
            if t in anchor_text:
                score += 2.0
            elif t in insight_text:
                score += 1.0
        if score > 0:
            scored.append((score, e))
    scored.sort(key=lambda s: (-s[0], s[1].get("id", "")))
    return [e for _s, e in scored[:MAX_RECALL]]


def reverify(G: nx.Graph, data: dict) -> dict:
    """Re-judge every entry against the current graph (self-sterilization).

    Still fully supported -> confirmations += 1. Any claim now REFUTED or
    UNKNOWN -> status becomes stale with the failing verdict recorded; a
    stale entry whose claims hold again (e.g. a revert) is resurrected.
    """
    from graphify.factcheck import Claim

    confirmed = 0
    quarantined = 0
    resurrected = 0
    for e in data.get("entries", []):
        claims = [
            Claim(str(c.get("subject", "")), str(c.get("relation", "")), str(c.get("object", "")))
            for c in e.get("claims", [])
        ]
        if not claims:
            continue
        verdicts = check_claims(G, claims)
        bad = next((v for v in verdicts if v.verdict in (REFUTED, UNKNOWN)), None)
        # refresh stored verdicts to the current judgment
        e["claims"] = _claims_payload(verdicts)
        if bad is None:
            e["confirmations"] = int(e.get("confirmations", 1)) + 1
            if e.get("status") == STATUS_STALE:
                e["status"] = STATUS_ACTIVE
                e["stale_reason"] = ""
                resurrected += 1
            else:
                confirmed += 1
        elif e.get("status") != STATUS_STALE:
            e["status"] = STATUS_STALE
            e["stale_reason"] = f"{bad.verdict}: {bad.evidence}"
            quarantined += 1
    return {
        "total": len(data.get("entries", [])),
        "confirmed": confirmed,
        "quarantined": quarantined,
        "resurrected": resurrected,
    }


# ── rendering ─────────────────────────────────────────────────────────────────

def render_entry(e: dict, *, full: bool = False) -> str:
    mark = "[ok]" if e.get("status") == STATUS_ACTIVE else "[zz]"
    lines = [f"{mark} {e.get('id')}: {e.get('insight')}"]
    meta = (f"     source={e.get('source')} confirmations={e.get('confirmations')}"
            f" anchors={', '.join(e.get('anchors', [])[:5])}")
    lines.append(meta)
    if e.get("status") == STATUS_STALE:
        lines.append(f"     STALE: {e.get('stale_reason')}")
    if full:
        for c in e.get("claims", []):
            lines.append(f"     - [{c.get('verdict')}] {c.get('subject')} "
                         f"{c.get('relation')} {c.get('object')}".rstrip())
    return "\n".join(lines)


def render_admission(status: str, entry: dict | None, verdicts: list[Verdict]) -> str:
    if status == ADMITTED and entry is not None:
        return (f"[ok] ADMITTED as {entry['id']}: every claim proved against the graph "
                f"({len(entry['claims'])} claim(s), anchors: "
                f"{', '.join(entry['anchors'][:5])})")
    if not verdicts:
        return ("[XX] REJECTED: no checkable claim found — sterile memory only "
                "stores insights the graph can prove")
    lines = ["[XX] REJECTED: the gate could not prove every claim:"]
    for v in verdicts:
        lines.append(f"  [{v.verdict}] {v.claim.subject} {v.claim.relation} "
                     f"{v.claim.object}".rstrip() + (f" — {v.evidence}" if v.evidence else ""))
    return "\n".join(lines)


def render_reverify(report: dict) -> str:
    return (f"re-sterilized {report['total']} memor(ies): "
            f"{report['confirmed']} confirmed, {report['quarantined']} quarantined, "
            f"{report['resurrected']} resurrected")
