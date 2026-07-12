"""Tests for factcheck.py - the hallucination gate.

A small directed graph stands in for graph.json: auth.py imports session.py,
login() calls validate_token(), Session inherits BaseModel. Claims are checked
mechanically; anything the graph can't back must come out UNKNOWN or REFUTED,
and correct claims must come out VERIFIED (never falsely refuted).
"""
import json

import networkx as nx
import pytest

from graphify.factcheck import (
    REFUTED,
    UNKNOWN,
    VERIFIED,
    VERIFIED_INDIRECT,
    Claim,
    check_claim,
    check_claims,
    extract_claims,
    parse_claims_json,
    render_report,
    run_verify,
    summarize,
)


def _graph() -> nx.DiGraph:
    G = nx.DiGraph()
    G.add_node("auth_py", label="auth.py", source_file="src/auth.py", file_type="code")
    G.add_node("session_py", label="session.py", source_file="src/session.py", file_type="code")
    G.add_node("auth_login", label="login()", source_file="src/auth.py", file_type="code")
    G.add_node("session_validate", label="validate_token()", source_file="src/session.py", file_type="code")
    G.add_node("session_cls", label="Session", source_file="src/session.py", file_type="code")
    G.add_node("base_model", label="BaseModel", source_file="src/models.py", file_type="code")
    G.add_node("lonely", label="OrphanWidget", source_file="src/widget.py", file_type="code")
    G.add_edge("auth_py", "session_py", relation="imports", confidence="EXTRACTED")
    G.add_edge("auth_py", "auth_login", relation="contains", confidence="EXTRACTED")
    G.add_edge("session_py", "session_validate", relation="contains", confidence="EXTRACTED")
    G.add_edge("auth_login", "session_validate", relation="calls", confidence="INFERRED")
    G.add_edge("session_cls", "base_model", relation="inherits", confidence="EXTRACTED")
    G.add_edge("session_py", "session_cls", relation="contains", confidence="EXTRACTED")
    return G


# ── direct verification ──────────────────────────────────────────────────────

def test_true_call_claim_is_verified():
    v = check_claim(_graph(), Claim("login()", "calls", "validate_token()"))
    assert v.verdict == VERIFIED
    assert v.confidence == "INFERRED"
    assert "login()" in v.evidence and "validate_token()" in v.evidence


def test_true_import_claim_is_verified():
    v = check_claim(_graph(), Claim("auth.py", "imports", "session.py"))
    assert v.verdict == VERIFIED
    assert v.confidence == "EXTRACTED"


def test_inherits_alias_extends_is_verified():
    v = check_claim(_graph(), Claim("Session", "extends", "BaseModel"))
    assert v.verdict == VERIFIED


def test_exists_claim_verified_and_missing_symbol_unknown():
    assert check_claim(_graph(), Claim("Session", "exists")).verdict == VERIFIED
    v = check_claim(_graph(), Claim("TotallyMadeUpSymbol", "exists"))
    assert v.verdict == UNKNOWN


# ── hallucination catching ───────────────────────────────────────────────────

def test_fabricated_connection_is_refuted():
    """OrphanWidget has no edges: claiming login() calls it must be REFUTED."""
    v = check_claim(_graph(), Claim("login()", "calls", "OrphanWidget"))
    assert v.verdict == REFUTED
    assert "no edge" in v.evidence


def test_reversed_direction_is_refuted():
    """Graph says login() calls validate_token(); the reverse claim is wrong."""
    v = check_claim(_graph(), Claim("validate_token()", "calls", "login()"))
    assert v.verdict == REFUTED
    assert "reversed" in v.evidence


def test_wrong_file_defined_in_is_refuted():
    v = check_claim(_graph(), Claim("validate_token()", "defined_in", "auth.py"))
    assert v.verdict == REFUTED
    assert "session.py" in v.evidence


def test_correct_defined_in_is_verified():
    v = check_claim(_graph(), Claim("validate_token()", "defined_in", "src/session.py"))
    assert v.verdict == VERIFIED


# ── indirect and safety behavior ─────────────────────────────────────────────

def test_two_hop_connection_is_indirect_not_refuted():
    """auth.py -> session.py -> Session: 'auth.py uses Session' isn't a direct
    edge but is connected, so it must not be refuted."""
    v = check_claim(_graph(), Claim("auth.py", "uses", "Session"))
    assert v.verdict == VERIFIED_INDIRECT
    assert v.path  # proof path present


def test_direct_edge_with_different_relation_is_indirect():
    v = check_claim(_graph(), Claim("auth.py", "references", "session.py"))
    assert v.verdict == VERIFIED_INDIRECT
    assert "imports" in v.evidence


def test_connected_pseudo_relation_accepts_any_edge():
    v = check_claim(_graph(), Claim("auth.py", "connected", "session.py"))
    assert v.verdict == VERIFIED


def test_max_hops_bounds_indirect_support():
    """With max_hops=1 the 3-hop auth.py->BaseModel support disappears; both
    endpoints are confident so the claim flips to REFUTED. (BaseModel, not
    Session: 'Session' also token-matches the session.py node, whose direct
    imports edge would legitimately support the claim at any hop bound.)"""
    assert check_claim(_graph(), Claim("auth.py", "uses", "BaseModel")).verdict == VERIFIED_INDIRECT
    v = check_claim(_graph(), Claim("auth.py", "uses", "BaseModel"), max_hops=1)
    assert v.verdict == REFUTED


def test_unresolvable_object_is_unknown_not_refuted():
    v = check_claim(_graph(), Claim("login()", "calls", "ImaginaryHelper"))
    assert v.verdict == UNKNOWN


def test_same_node_endpoints_are_unknown():
    v = check_claim(_graph(), Claim("login()", "calls", "login"))
    assert v.verdict == UNKNOWN


# ── text extraction ──────────────────────────────────────────────────────────

def test_extract_claims_finds_relation_sentence():
    text = "The `login()` function calls `validate_token()` to check the session."
    claims = extract_claims(text)
    assert any(
        c.relation == "calls" and c.subject == "login()" and c.object == "validate_token()"
        for c in claims
    )


def test_extract_claims_defined_in():
    claims = extract_claims("`validate_token()` is defined in session.py.")
    assert any(c.relation == "defined_in" and c.object == "session.py" for c in claims)


def test_extract_claims_lone_identifiers_become_exists():
    claims = extract_claims("Look at `BaseModel` for the shared fields.")
    assert any(c.relation == "exists" and c.subject == "BaseModel" for c in claims)


def test_extract_claims_plain_prose_yields_nothing():
    assert extract_claims("This code is generally well structured and fast.") == []


def test_extract_claims_dedupes():
    text = "`a_func()` calls `b_func()`. Again: `a_func()` calls `b_func()`."
    claims = [c for c in extract_claims(text) if c.relation == "calls"]
    assert len(claims) == 1


# ── JSON interface, summary, report ──────────────────────────────────────────

def test_parse_claims_json_list_and_wrapper():
    raw = json.dumps([{"subject": "A", "relation": "calls", "object": "B"}])
    assert parse_claims_json(raw)[0].subject == "A"
    wrapped = json.dumps({"claims": [{"subject": "A", "relation": "exists"}]})
    assert parse_claims_json(wrapped)[0].relation == "exists"


def test_parse_claims_json_rejects_malformed():
    with pytest.raises(ValueError):
        parse_claims_json(json.dumps([{"relation": "calls"}]))
    with pytest.raises(ValueError):
        parse_claims_json(json.dumps("nope"))


def test_summarize_and_report_counts():
    G = _graph()
    verdicts = check_claims(G, [
        Claim("login()", "calls", "validate_token()"),
        Claim("validate_token()", "calls", "login()"),
        Claim("NopeSymbol", "exists"),
    ])
    s = summarize(verdicts)
    assert s["total"] == 3 and s["verified"] == 1 and s["refuted"] == 1 and s["unknown"] == 1
    report = render_report(verdicts)
    assert "REFUTED" in report and "3 claim(s)" in report


# ── end-to-end against a real graph.json file ────────────────────────────────

def _write_graph_json(tmp_path):
    G = _graph()
    from networkx.readwrite import json_graph
    data = json_graph.node_link_data(G, edges="links")
    p = tmp_path / "graphify-out" / "graph.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_run_verify_text_against_graph_file(tmp_path):
    gp = _write_graph_json(tmp_path)
    verdicts, summary = run_verify(
        gp, text="`login()` calls `validate_token()`. `validate_token()` calls `login()`."
    )
    by = {(v.claim.subject, v.claim.object): v.verdict for v in verdicts}
    assert by[("login()", "validate_token()")] == VERIFIED
    assert by[("validate_token()", "login()")] == REFUTED
    assert summary["refuted"] == 1


def test_run_verify_claims_json_against_graph_file(tmp_path):
    gp = _write_graph_json(tmp_path)
    raw = json.dumps([{"subject": "auth.py", "relation": "imports", "object": "session.py"}])
    verdicts, summary = run_verify(gp, claims_json=raw)
    assert verdicts[0].verdict == VERIFIED
    assert summary["verified"] == 1


def test_run_verify_requires_exactly_one_input(tmp_path):
    gp = _write_graph_json(tmp_path)
    with pytest.raises(ValueError):
        run_verify(gp)
    with pytest.raises(ValueError):
        run_verify(gp, text="x", claims_json="[]")
