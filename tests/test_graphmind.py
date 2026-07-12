"""Tests for graphmind.py - the graph-ops thinking engine.

Small directed graph: routes.py contains get_user(), which calls fetch_user()
in service.py, which calls run_query() in db.py. Ops are executed as a driving
model would emit them; results must be compact, deterministic, and grounded.
"""
import json

import networkx as nx

from graphify.graphmind import (
    MindSession,
    OPS_HELP,
    SESSION_FILENAME,
    _parse_op_reply,
    load_session,
    save_session,
    think,
)


def _graph() -> nx.DiGraph:
    G = nx.DiGraph()
    G.add_node("routes_py", label="routes.py", source_file="src/routes.py")
    G.add_node("get_user", label="get_user()", source_file="src/routes.py",
               source_location="L10", community=1, community_name="http layer")
    G.add_node("svc_py", label="service.py", source_file="src/service.py")
    G.add_node("fetch_user", label="fetch_user()", source_file="src/service.py",
               community=2, community_name="domain")
    G.add_node("db_py", label="db.py", source_file="src/db.py")
    G.add_node("run_query", label="run_query()", source_file="src/db.py",
               community=3, community_name="storage")
    G.add_edge("routes_py", "get_user", relation="contains", confidence="EXTRACTED")
    G.add_edge("svc_py", "fetch_user", relation="contains", confidence="EXTRACTED")
    G.add_edge("db_py", "run_query", relation="contains", confidence="EXTRACTED")
    G.add_edge("get_user", "fetch_user", relation="calls", confidence="EXTRACTED")
    G.add_edge("fetch_user", "run_query", relation="calls", confidence="INFERRED")
    return G


# ── individual ops ────────────────────────────────────────────────────────────

def test_find_assigns_refs_and_lists_matches():
    s = MindSession(_graph())
    out = s.execute("find fetch_user")
    assert "n1:fetch_user()" in out
    assert "src/service.py" in out


def test_refs_are_stable_across_ops():
    s = MindSession(_graph())
    s.execute("find fetch_user")           # fetch_user -> n1
    out = s.execute("callers n1")
    assert "get_user()" in out
    out2 = s.execute("find fetch_user")    # same node keeps the same ref
    assert "n1:fetch_user()" in out2


def test_callers_and_callees_directions():
    s = MindSession(_graph())
    s.execute("find fetch_user")
    callers = s.execute("callers n1")
    callees = s.execute("callees n1")
    assert "get_user()" in callers and "run_query" not in callers
    assert "run_query()" in callees and "get_user" not in callees


def test_members_lists_contains():
    s = MindSession(_graph())
    out = s.execute('members "routes.py"')
    assert "get_user()" in out


def test_expand_in_filters_direction():
    s = MindSession(_graph())
    s.execute("find run_query")
    out = s.execute("expand n1 in")
    assert "fetch_user()" in out and "contains" in out or "calls" in out


def test_path_renders_hops_with_relations():
    s = MindSession(_graph())
    out = s.execute('path "get_user()" -> "run_query()"')
    assert "2 hop(s)" in out
    assert "--calls-->" in out


def test_common_neighbors():
    s = MindSession(_graph())
    out = s.execute('common "get_user()" -> "run_query()"')
    assert "fetch_user()" in out


def test_source_reports_location_and_confidence_free():
    s = MindSession(_graph())
    out = s.execute('source "get_user()"')
    assert "src/routes.py" in out and "L10" in out


def test_community_lists_membership():
    s = MindSession(_graph())
    out = s.execute('community "fetch_user()"')
    assert "domain" in out


def test_scars_op_reports_file_history():
    scars = {
        "version": 1,
        "files": {
            "src/service.py": {
                "path": "src/service.py", "edits": 10, "fix_edits": 4,
                "revert_edits": 1, "danger": 0.6,
                "couples": [{"path": "src/db.py", "support": 5, "confidence": 0.5}],
            }
        },
    }
    s = MindSession(_graph(), scars)
    out = s.execute('scars "fetch_user()"')
    assert "danger 0.6" in out and "src/db.py" in out


def test_memory_op_recalls_verified_insights():
    mem = {
        "version": 1, "next_id": 2,
        "entries": [{
            "id": "m1", "insight": "fetch_user() is the domain seam.",
            "status": "active", "source": "think", "confirmations": 2,
            "stale_reason": "", "anchors": ["fetch_user()", "service.py"],
            "claims": [],
        }],
    }
    s = MindSession(_graph(), None, mem)
    out = s.execute("memory fetch_user")
    assert "m1" in out and "domain seam" in out


def test_memory_op_without_store_explains_how():
    s = MindSession(_graph())
    out = s.execute("memory fetch_user")
    assert "sanad memory add" in out or "no memories" in out


def test_scars_op_without_data_explains_how_to_get_it():
    s = MindSession(_graph())
    out = s.execute('scars "fetch_user()"')
    assert "sanad scars" in out


def test_note_and_notes_roundtrip():
    s = MindSession(_graph())
    s.execute("note fetch_user is the domain seam")
    out = s.execute("notes")
    assert "domain seam" in out


def test_answer_records_and_reports():
    s = MindSession(_graph())
    out = s.execute("answer get_user -> fetch_user -> run_query")
    assert out == "answer recorded"
    assert s.answer.startswith("get_user")


# ── error behavior: the model must SEE its mistakes, not crash the loop ──────

def test_unknown_op_returns_error_string():
    s = MindSession(_graph())
    out = s.execute("teleport n1")
    assert out.startswith("error:") and "help" in out


def test_unknown_ref_returns_error_string():
    s = MindSession(_graph())
    out = s.execute("callers n99")
    assert out.startswith("error:") and "n99" in out


def test_unresolvable_label_suggests_find():
    s = MindSession(_graph())
    out = s.execute('callers "does_not_exist_anywhere()"')
    assert out.startswith("error:") and "find" in out


def test_malformed_path_usage():
    s = MindSession(_graph())
    assert s.execute("path just_one_side").startswith("error:")


def test_help_returns_ops_language():
    s = MindSession(_graph())
    assert s.execute("help") == OPS_HELP


# ── result compactness (token budget is the whole point) ─────────────────────

def test_expand_caps_long_neighbor_lists():
    G = _graph()
    for i in range(40):
        nid = f"extra{i}"
        G.add_node(nid, label=f"extra{i}()", source_file="src/extra.py")
        G.add_edge(nid, "run_query", relation="calls")
    s = MindSession(G)
    out = s.execute('callers "run_query()"')
    assert "+29 more" in out
    assert len(out.splitlines()) <= 15


# ── session persistence (drives `graphify ops` across invocations) ──────────

def test_session_save_load_keeps_refs_notes_history(tmp_path):
    G = _graph()
    s = MindSession(G)
    s.execute("find fetch_user")
    s.execute("note the seam is fetch_user")
    save_session(tmp_path, s)
    assert (tmp_path / SESSION_FILENAME).exists()

    s2 = load_session(tmp_path, G)
    assert s2.notes == ["the seam is fetch_user"]
    assert s2.history[0] == "find fetch_user"
    out = s2.execute("callers n1")  # ref n1 survives the round-trip
    assert "get_user()" in out


def test_load_session_missing_or_corrupt_starts_fresh(tmp_path):
    G = _graph()
    assert load_session(tmp_path, G).ref_ids == []
    (tmp_path / SESSION_FILENAME).write_text("{not json", encoding="utf-8")
    assert load_session(tmp_path, G).ref_ids == []


# ── think loop with a scripted fake backend ──────────────────────────────────

def test_parse_op_reply_extracts_first_op_line():
    assert _parse_op_reply("Sure! Here's my op:\n\nfind login\n") == "find login"
    assert _parse_op_reply("`callers n1`") == "callers n1"
    assert _parse_op_reply("answer it flows a->b") == "answer it flows a->b"
    assert _parse_op_reply("") == ""


def test_think_loop_runs_ops_until_answer(monkeypatch):
    scripted = iter([
        "find fetch_user",
        "callers n1",
        "callees n1",
        "answer get_user() calls fetch_user() which calls run_query() (src/service.py).",
    ])

    def fake_call(prompt, *, backend, model=None, max_tokens=0, usage_out=None):
        assert backend == "gemini"
        # The transcript must carry compact results, not raw source code.
        assert "def " not in prompt
        if usage_out is not None:
            usage_out["input"] = usage_out.get("input", 0) + 100
            usage_out["output"] = usage_out.get("output", 0) + 10
        return next(scripted)

    monkeypatch.setattr("graphify.llm._call_llm", fake_call)
    usage: dict = {}
    answer, trace = think(_graph(), "How does a request reach the database?",
                          backend="gemini", budget=10, usage_out=usage)
    assert answer is not None and "run_query" in answer
    assert [op for op, _ in trace][:3] == ["find fetch_user", "callers n1", "callees n1"]
    assert usage["input"] == 400  # 4 calls happened, budget not exhausted


def test_think_loop_stops_at_budget(monkeypatch):
    monkeypatch.setattr(
        "graphify.llm._call_llm",
        lambda prompt, **kw: "find fetch_user",
    )
    answer, trace = think(_graph(), "q", backend="gemini", budget=3)
    assert answer is None
    assert len(trace) == 3


def test_think_loop_surfaces_model_errors_in_trace(monkeypatch):
    scripted = iter(["gibberish nonsense", "answer done"])
    monkeypatch.setattr(
        "graphify.llm._call_llm",
        lambda prompt, **kw: next(scripted),
    )
    answer, trace = think(_graph(), "q", backend="gemini", budget=5)
    assert answer == "done"
    assert trace[0][1].startswith("error:")
