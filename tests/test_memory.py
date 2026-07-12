"""Tests for memory.py - the sterile memory store.

Same auth/session graph as the factcheck tests: `login()` calls
`validate_token()` and Session inherits BaseModel. A true insight must be
admitted with anchors, a poisoned one rejected with the gate report, and
reverify must quarantine an entry the moment its claims stop holding —
then resurrect it if the graph reverts.
"""
import json

import networkx as nx

from graphify.memory import (
    ADMITTED,
    MEMORY_FILENAME,
    REJECTED,
    STATUS_ACTIVE,
    STATUS_STALE,
    admit,
    forget,
    load_memory,
    recall,
    render_admission,
    render_entry,
    render_reverify,
    reverify,
    save_memory,
)


def _graph() -> nx.DiGraph:
    G = nx.DiGraph()
    G.add_node("auth_py", label="auth.py", source_file="src/auth.py", file_type="code")
    G.add_node("login", label="login()", source_file="src/auth.py", file_type="code")
    G.add_node("validate", label="validate_token()", source_file="src/session.py", file_type="code")
    G.add_node("session_cls", label="Session", source_file="src/session.py", file_type="code")
    G.add_node("base", label="BaseModel", source_file="src/models.py", file_type="code")
    G.add_edge("auth_py", "login", relation="contains", confidence="EXTRACTED")
    G.add_edge("login", "validate", relation="calls", confidence="EXTRACTED")
    G.add_edge("session_cls", "base", relation="inherits", confidence="EXTRACTED")
    return G


def _store() -> dict:
    return {"version": 1, "next_id": 1, "entries": []}


TRUE_INSIGHT = "`login()` calls `validate_token()` to authenticate requests."
LIE_INSIGHT = "`validate_token()` calls `login()` on every request."


# ── admission ─────────────────────────────────────────────────────────────────

def test_true_insight_is_admitted_with_anchors():
    data = _store()
    status, entry, verdicts = admit(_graph(), data, TRUE_INSIGHT, source="think")
    assert status == ADMITTED
    assert entry["id"] == "m1" and entry["status"] == STATUS_ACTIVE
    assert "login()" in entry["anchors"] and "validate_token()" in entry["anchors"]
    assert data["entries"] == [entry] and data["next_id"] == 2


def test_lying_insight_is_rejected_with_gate_report():
    data = _store()
    status, entry, verdicts = admit(_graph(), data, LIE_INSIGHT)
    assert status == REJECTED and entry is None
    assert data["entries"] == []
    report = render_admission(status, entry, verdicts)
    assert "REJECTED" in report and "REFUTED" in report


def test_unprovable_insight_is_rejected():
    data = _store()
    status, entry, _ = admit(_graph(), data, "`ghost_helper()` calls `login()`.")
    assert status == REJECTED and data["entries"] == []


def test_claimless_prose_is_rejected():
    data = _store()
    status, entry, verdicts = admit(_graph(), data, "This code is quite elegant overall.")
    assert status == REJECTED and verdicts == []
    assert "no checkable claim" in render_admission(status, entry, verdicts)


def test_ids_increment_across_admissions():
    data = _store()
    admit(_graph(), data, TRUE_INSIGHT)
    status, entry, _ = admit(_graph(), data, "`Session` inherits `BaseModel`.")
    assert status == ADMITTED and entry["id"] == "m2"


# ── recall ────────────────────────────────────────────────────────────────────

def test_recall_matches_anchors_first():
    data = _store()
    admit(_graph(), data, TRUE_INSIGHT)
    admit(_graph(), data, "`Session` inherits `BaseModel`.")
    hits = recall(data, "how does validate_token work")
    assert hits and hits[0]["id"] == "m1"


def test_recall_excludes_stale_by_default():
    data = _store()
    admit(_graph(), data, TRUE_INSIGHT)
    data["entries"][0]["status"] = STATUS_STALE
    assert recall(data, "validate_token") == []
    assert recall(data, "validate_token", include_stale=True)


def test_recall_empty_query_or_no_match():
    data = _store()
    admit(_graph(), data, TRUE_INSIGHT)
    assert recall(data, "") == []
    assert recall(data, "zzz qqq") == []


# ── re-sterilization ──────────────────────────────────────────────────────────

def test_reverify_confirms_when_claims_still_hold():
    data = _store()
    admit(_graph(), data, TRUE_INSIGHT)
    report = reverify(_graph(), data)
    assert report["confirmed"] == 1 and report["quarantined"] == 0
    assert data["entries"][0]["confirmations"] == 2


def test_reverify_quarantines_when_code_changes():
    data = _store()
    admit(_graph(), data, TRUE_INSIGHT)
    G2 = _graph()
    G2.remove_edge("login", "validate")  # the call disappears from the code
    report = reverify(G2, data)
    assert report["quarantined"] == 1
    e = data["entries"][0]
    assert e["status"] == STATUS_STALE and e["stale_reason"]
    assert "STALE" in render_entry(e)


def test_reverify_resurrects_when_graph_reverts():
    data = _store()
    admit(_graph(), data, TRUE_INSIGHT)
    G2 = _graph()
    G2.remove_edge("login", "validate")
    reverify(G2, data)
    report = reverify(_graph(), data)  # the revert restores the edge
    assert report["resurrected"] == 1
    assert data["entries"][0]["status"] == STATUS_ACTIVE
    assert "re-sterilized" in render_reverify(report)


# ── persistence + forget ─────────────────────────────────────────────────────

def test_sidecar_round_trip(tmp_path):
    data = _store()
    admit(_graph(), data, TRUE_INSIGHT)
    p = save_memory(tmp_path, data)
    assert p.name == MEMORY_FILENAME
    loaded = load_memory(tmp_path)
    assert loaded["entries"][0]["insight"] == data["entries"][0]["insight"]
    assert loaded["next_id"] == 2


def test_load_memory_missing_or_corrupt(tmp_path):
    assert load_memory(tmp_path)["entries"] == []
    (tmp_path / MEMORY_FILENAME).write_text("{oops", encoding="utf-8")
    assert load_memory(tmp_path)["entries"] == []


def test_forget_removes_only_the_target():
    data = _store()
    admit(_graph(), data, TRUE_INSIGHT)
    admit(_graph(), data, "`Session` inherits `BaseModel`.")
    assert forget(data, "m1") is True
    assert [e["id"] for e in data["entries"]] == ["m2"]
    assert forget(data, "m99") is False
