"""Tests for impact.py - the edit blast-radius oracle.

Small directed graph: handlers.py calls into service.py, which calls into
db.py. Editing db.py should predict service.py and handlers.py as blast
radius; a post-edit change confined to those files is CLEAN, a change in an
unrelated file is a DEVIATION.
"""
import json

import networkx as nx
import pytest

from graphify.impact import (
    BASELINE_FILENAME,
    CLEAN,
    CONTRACT_FILENAME,
    DEVIATION,
    NO_CHANGES,
    check_impact,
    diff_changed_files,
    load_baseline,
    load_contract,
    predict_impact,
    render_check,
    render_prediction,
    write_contract,
)


def _graph() -> nx.DiGraph:
    G = nx.DiGraph()
    G.add_node("db_py", label="db.py", source_file="src/db.py")
    G.add_node("db_query", label="run_query()", source_file="src/db.py")
    G.add_node("svc_py", label="service.py", source_file="src/service.py")
    G.add_node("svc_fetch", label="fetch_user()", source_file="src/service.py")
    G.add_node("h_py", label="handlers.py", source_file="src/handlers.py")
    G.add_node("h_get", label="get_user_handler()", source_file="src/handlers.py")
    G.add_node("util_py", label="strings.py", source_file="src/strings.py")
    G.add_edge("db_py", "db_query", relation="contains", confidence="EXTRACTED")
    G.add_edge("svc_py", "svc_fetch", relation="contains", confidence="EXTRACTED")
    G.add_edge("h_py", "h_get", relation="contains", confidence="EXTRACTED")
    G.add_edge("svc_fetch", "db_query", relation="calls", confidence="EXTRACTED")
    G.add_edge("h_get", "svc_fetch", relation="calls", confidence="EXTRACTED")
    G.add_edge("svc_py", "db_py", relation="imports", confidence="EXTRACTED")
    return G


def _clone(G: nx.DiGraph) -> nx.DiGraph:
    return G.copy()


# ── prediction ────────────────────────────────────────────────────────────────

def test_predict_walks_reverse_dependencies():
    contract = predict_impact(_graph(), ["run_query()"], depth=2)
    files = set(contract["predicted_files"])
    # depth 1: fetch_user calls run_query; depth 2: get_user_handler calls fetch_user
    assert "src/service.py" in files
    assert "src/handlers.py" in files
    assert "src/strings.py" not in files
    labels = {n["label"] for n in contract["predicted_nodes"]}
    assert "fetch_user()" in labels and "get_user_handler()" in labels


def test_predict_depth_limits_radius():
    contract = predict_impact(_graph(), ["run_query()"], depth=1)
    labels = {n["label"] for n in contract["predicted_nodes"]}
    assert "fetch_user()" in labels
    assert "get_user_handler()" not in labels


def test_predict_file_target_resolves_to_file_node():
    contract = predict_impact(_graph(), ["src/db.py"], depth=2)
    assert contract["targets"][0]["label"] == "db.py"
    assert "src/service.py" in contract["predicted_files"]


def test_predict_unresolvable_target_raises():
    with pytest.raises(ValueError, match="no unique node match"):
        predict_impact(_graph(), ["definitely_not_a_symbol()"])


def test_predict_requires_targets():
    with pytest.raises(ValueError):
        predict_impact(_graph(), [])


def test_render_prediction_mentions_files():
    contract = predict_impact(_graph(), ["run_query()"], depth=2)
    text = render_prediction(contract)
    assert "src/service.py" in text and "check-impact" in text


# ── diffing ───────────────────────────────────────────────────────────────────

def test_diff_identical_graphs_is_empty():
    assert diff_changed_files(_graph(), _graph()) == []


def test_diff_detects_added_node_and_edge():
    old, new = _graph(), _graph()
    new.add_node("svc_new", label="new_helper()", source_file="src/service.py")
    new.add_edge("svc_py", "svc_new", relation="contains")
    assert diff_changed_files(old, new) == ["src/service.py"]


def test_diff_detects_removed_node():
    old, new = _graph(), _graph()
    new.remove_node("h_get")
    changed = diff_changed_files(old, new)
    # h_get's removal also removes its call edge, whose other endpoint lives
    # in service.py — both files legitimately changed.
    assert "src/handlers.py" in changed
    assert "src/service.py" in changed


# ── check_impact verdicts ─────────────────────────────────────────────────────

def _contract():
    return predict_impact(_graph(), ["run_query()"], depth=2)


def test_check_no_changes():
    report = check_impact(_contract(), _graph(), _graph())
    assert report["verdict"] == NO_CHANGES


def test_check_clean_when_change_is_inside_prediction():
    new = _clone(_graph())
    new.add_node("svc_new", label="retry_wrapper()", source_file="src/service.py")
    new.add_edge("svc_py", "svc_new", relation="contains")
    report = check_impact(_contract(), _graph(), new)
    assert report["verdict"] == CLEAN
    assert report["inside_contract"] == ["src/service.py"]
    assert report["outside_contract"] == []


def test_check_target_file_change_is_clean():
    """Changing the edit target itself is obviously in-contract."""
    contract = predict_impact(_graph(), ["src/db.py"], depth=2)
    new = _clone(_graph())
    new.add_node("db_new", label="pool()", source_file="src/db.py")
    new.add_edge("db_py", "db_new", relation="contains")
    report = check_impact(contract, _graph(), new)
    assert report["verdict"] == CLEAN


def test_check_deviation_when_unrelated_file_changes():
    new = _clone(_graph())
    new.add_node("util_new", label="slugify()", source_file="src/strings.py")
    new.add_edge("util_py", "util_new", relation="contains")
    report = check_impact(_contract(), _graph(), new)
    assert report["verdict"] == DEVIATION
    assert report["outside_contract"] == ["src/strings.py"]


def test_check_mixed_changes_still_deviation():
    new = _clone(_graph())
    new.add_node("svc_new", label="retry_wrapper()", source_file="src/service.py")
    new.add_edge("svc_py", "svc_new", relation="contains")
    new.add_node("util_new", label="slugify()", source_file="src/strings.py")
    new.add_edge("util_py", "util_new", relation="contains")
    report = check_impact(_contract(), _graph(), new)
    assert report["verdict"] == DEVIATION
    assert report["inside_contract"] == ["src/service.py"]
    assert report["outside_contract"] == ["src/strings.py"]


def test_render_check_marks_deviation():
    new = _clone(_graph())
    new.add_node("util_new", label="slugify()", source_file="src/strings.py")
    report = check_impact(_contract(), _graph(), new)
    text = render_check(report)
    assert "DEVIATION" in text and "src/strings.py" in text


# ── persistence round-trip ────────────────────────────────────────────────────

def _write_graph_json(G, path):
    from networkx.readwrite import json_graph
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_graph.node_link_data(G, edges="links")), encoding="utf-8")


def test_contract_and_baseline_round_trip(tmp_path):
    out = tmp_path / "graphify-out"
    graph_path = out / "graph.json"
    _write_graph_json(_graph(), graph_path)

    contract = predict_impact(_graph(), ["run_query()"], depth=2)
    write_contract(out, contract, graph_path)
    assert (out / CONTRACT_FILENAME).exists()
    assert (out / BASELINE_FILENAME).exists()

    loaded = load_contract(out)
    assert loaded["predicted_files"] == contract["predicted_files"]
    baseline = load_baseline(out)
    assert diff_changed_files(baseline, _graph()) == []


def test_load_contract_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="graphify predict"):
        load_contract(tmp_path)
    with pytest.raises(FileNotFoundError):
        load_baseline(tmp_path)


def test_full_cycle_against_files(tmp_path):
    """predict -> (simulated edit rebuild) -> check, all through the on-disk
    artifacts exactly as the CLI drives them."""
    out = tmp_path / "graphify-out"
    graph_path = out / "graph.json"
    G0 = _graph()
    _write_graph_json(G0, graph_path)

    contract = predict_impact(G0, ["run_query()"], depth=2)
    write_contract(out, contract, graph_path)

    # Simulated rebuild after an edit that ripples into an unpredicted file.
    G1 = _clone(G0)
    G1.add_node("util_new", label="slugify()", source_file="src/strings.py")
    _write_graph_json(G1, graph_path)

    from graphify.impact import load_graph
    report = check_impact(load_contract(out), load_baseline(out), load_graph(graph_path))
    assert report["verdict"] == DEVIATION
    assert report["outside_contract"] == ["src/strings.py"]
