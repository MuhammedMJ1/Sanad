"""Tests for council.py - the lens debate council.

A scripted fake backend plays every voice: each lens runs a graph-ops loop,
reconciliation merges the voices, and the factcheck gate forces a revision
when the consensus contains a refuted claim.
"""
import networkx as nx
import pytest

from graphify.council import (
    DEFAULT_LENSES,
    LENSES,
    CouncilResult,
    convene,
    render_result,
)


def _graph() -> nx.DiGraph:
    G = nx.DiGraph()
    G.add_node("routes_py", label="routes.py", source_file="src/routes.py")
    G.add_node("get_user", label="get_user()", source_file="src/routes.py")
    G.add_node("svc_py", label="service.py", source_file="src/service.py")
    G.add_node("fetch_user", label="fetch_user()", source_file="src/service.py")
    G.add_node("db_py", label="db.py", source_file="src/db.py")
    G.add_node("run_query", label="run_query()", source_file="src/db.py")
    G.add_edge("routes_py", "get_user", relation="contains", confidence="EXTRACTED")
    G.add_edge("svc_py", "fetch_user", relation="contains", confidence="EXTRACTED")
    G.add_edge("db_py", "run_query", relation="contains", confidence="EXTRACTED")
    G.add_edge("get_user", "fetch_user", relation="calls", confidence="EXTRACTED")
    G.add_edge("fetch_user", "run_query", relation="calls", confidence="INFERRED")
    return G


class ScriptedBackend:
    """Answers _call_llm calls from a queue and records every prompt."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.prompts: list[str] = []

    def __call__(self, prompt, *, backend, model=None, max_tokens=0, usage_out=None):
        self.prompts.append(prompt)
        if usage_out is not None:
            usage_out["input"] = usage_out.get("input", 0) + 50
            usage_out["output"] = usage_out.get("output", 0) + 10
        if not self.replies:
            raise AssertionError("scripted backend ran out of replies")
        return self.replies.pop(0)


def _patch(monkeypatch, backend: ScriptedBackend):
    monkeypatch.setattr("graphify.llm._call_llm", backend)


# ── happy path: three voices, clean consensus ─────────────────────────────────

def test_council_full_flow_clean(monkeypatch):
    fake = ScriptedBackend([
        # callers voice (2 ops)
        "find fetch_user",
        "answer fetch_user() is called by get_user() (src/routes.py).",
        # callees voice (2 ops)
        "find fetch_user",
        "answer fetch_user() calls run_query() (src/db.py).",
        # structure voice (1 op)
        "answer `fetch_user()` is defined in service.py between routes and db.",
        # reconciliation
        "`fetch_user()` is the seam: `get_user()` calls `fetch_user()`, "
        "which calls `run_query()`.",
    ])
    _patch(monkeypatch, fake)
    usage: dict = {}
    result = convene(_graph(), "What role does fetch_user play?",
                     backend="gemini", usage_out=usage)
    assert isinstance(result, CouncilResult)
    assert [r.name for r in result.lens_reports] == list(DEFAULT_LENSES)
    assert all(r.answer for r in result.lens_reports)
    assert "seam" in result.final_answer
    # Gate ran and found nothing to refute (all claims are true in the graph).
    assert result.gate_summary["refuted"] == 0
    assert result.revisions == 0
    assert usage["input"] > 0


def test_each_lens_receives_its_perspective(monkeypatch):
    fake = ScriptedBackend([
        "answer a", "answer b", "answer c",   # one op per voice
        "consensus",                           # reconciliation
    ])
    _patch(monkeypatch, fake)
    convene(_graph(), "q", backend="gemini", verify=False)
    lens_prompts = fake.prompts[:3]
    assert "USAGE voice" in lens_prompts[0]
    assert "DEPENDENCY voice" in lens_prompts[1]
    assert "ARCHITECTURE voice" in lens_prompts[2]


def test_reconciliation_carries_voice_answers_not_transcripts(monkeypatch):
    fake = ScriptedBackend([
        "find fetch_user",
        "answer inbound: get_user calls it.",
        "answer outbound: it calls run_query.",
        "answer structure: lives in service.py.",
        "consensus",
    ])
    _patch(monkeypatch, fake)
    convene(_graph(), "q", backend="gemini", verify=False)
    reconcile_prompt = fake.prompts[-1]
    assert "[callers voice] inbound" in reconcile_prompt
    assert "[callees voice] outbound" in reconcile_prompt
    # op transcripts must NOT leak into reconciliation (token discipline)
    assert "find fetch_user" not in reconcile_prompt


# ── gate-forced revision ──────────────────────────────────────────────────────

def test_refuted_consensus_forces_revision(monkeypatch):
    fake = ScriptedBackend([
        "answer a", "answer b", "answer c",
        # consensus with a claim the graph refutes (wrong file)
        "`fetch_user()` is defined in db.py.",
        # revision (correct)
        "`fetch_user()` is defined in service.py.",
    ])
    _patch(monkeypatch, fake)
    result = convene(_graph(), "q", backend="gemini")
    assert result.revisions == 1
    assert result.gate_summary["refuted"] == 0
    assert "service.py" in result.final_answer
    # the revision prompt carried the gate's mechanical evidence
    assert "REFUTED" in fake.prompts[-1]


def test_revision_capped_even_if_still_refuted(monkeypatch):
    fake = ScriptedBackend([
        "answer a", "answer b", "answer c",
        "`fetch_user()` is defined in db.py.",      # refuted consensus
        "`fetch_user()` is defined in routes.py.",  # still refuted after revision
    ])
    _patch(monkeypatch, fake)
    result = convene(_graph(), "q", backend="gemini", max_revisions=1)
    assert result.revisions == 1
    assert result.gate_summary["refuted"] >= 1  # honest: still failing


def test_no_verify_skips_gate(monkeypatch):
    fake = ScriptedBackend([
        "answer a", "answer b", "answer c",
        "`fetch_user()` is defined in db.py.",  # would be refuted if gated
    ])
    _patch(monkeypatch, fake)
    result = convene(_graph(), "q", backend="gemini", verify=False)
    assert result.revisions == 0
    assert result.gate_report == ""


# ── failure and config behavior ───────────────────────────────────────────────

def test_unknown_lens_raises():
    with pytest.raises(ValueError, match="unknown lens"):
        convene(_graph(), "q", backend="gemini", lenses=("callers", "psychic"))


def test_all_voices_silent_raises(monkeypatch):
    fake = ScriptedBackend(["find x"] * 6)  # never answers within budget
    _patch(monkeypatch, fake)
    with pytest.raises(RuntimeError, match="no lens produced an answer"):
        convene(_graph(), "q", backend="gemini",
                lenses=("callers", "callees"), budget_per_lens=3)


def test_partial_voices_still_reconcile(monkeypatch):
    fake = ScriptedBackend([
        "find x", "find x",   # callers voice exhausts budget (2), no answer
        "answer outbound story.",
        "consensus from one voice",
    ])
    _patch(monkeypatch, fake)
    result = convene(_graph(), "q", backend="gemini",
                     lenses=("callers", "callees"), budget_per_lens=2,
                     verify=False)
    assert result.lens_reports[0].answer is None
    assert result.lens_reports[1].answer == "outbound story."
    assert result.final_answer == "consensus from one voice"


def test_evidence_lens_exists_and_is_selectable(monkeypatch):
    assert "evidence" in LENSES
    fake = ScriptedBackend(["answer tests cover it.", "consensus"])
    _patch(monkeypatch, fake)
    result = convene(_graph(), "q", backend="gemini",
                     lenses=("evidence",), verify=False)
    assert result.lens_reports[0].name == "evidence"


# ── rendering and serialization ───────────────────────────────────────────────

def test_render_result_shows_voices_consensus_and_gate(monkeypatch):
    fake = ScriptedBackend([
        "answer inbound.", "answer outbound.", "answer structure.",
        "`fetch_user()` is defined in service.py.",
    ])
    _patch(monkeypatch, fake)
    result = convene(_graph(), "q", backend="gemini")
    text = render_result(result)
    assert "[callers voice" in text
    assert "Consensus:" in text
    assert "hallucination gate" in text


def test_to_dict_is_json_shaped(monkeypatch):
    import json
    fake = ScriptedBackend(["answer a.", "answer b.", "answer c.", "done."])
    _patch(monkeypatch, fake)
    result = convene(_graph(), "q", backend="gemini", verify=False)
    d = result.to_dict()
    json.dumps(d)  # must serialize
    assert d["final_answer"] == "done."
    assert len(d["lenses"]) == 3
