"""Tests for windtunnel.py - graph-sliced sandbox with real execution.

A mini repo on disk (pkg/api.py -> pkg/core.py -> pkg/util.py, plus an
unrelated pkg/other.py and a test file) with a matching graph. The slice must
be the minimal import closure, the sandbox must really import and really run
pytest, and a poisoned draft must fail the smoke phase with a real traceback.
"""
from pathlib import Path

import networkx as nx
import pytest

from graphify.windtunnel import (
    Slice,
    materialize,
    render_report,
    run_smoke,
    run_tests,
    slice_files,
    wind_tunnel,
)
from graphify.windtunnel import tests_for as _tests_for  # alias: pytest must not collect it


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "pkg" / "util.py").write_text(
        "def double(x):\n    return x * 2\n", encoding="utf-8")
    (repo / "pkg" / "core.py").write_text(
        "from pkg.util import double\n\ndef compute(x):\n    return double(x) + 1\n",
        encoding="utf-8")
    (repo / "pkg" / "api.py").write_text(
        "from pkg.core import compute\n\ndef handle(x):\n    return compute(x)\n",
        encoding="utf-8")
    (repo / "pkg" / "other.py").write_text(
        "def unrelated():\n    return 42\n", encoding="utf-8")
    (repo / "tests" / "test_core.py").write_text(
        "from pkg.core import compute\n\ndef test_compute():\n    assert compute(2) == 5\n",
        encoding="utf-8")
    return repo


def _graph() -> nx.DiGraph:
    G = nx.DiGraph()
    G.add_node("api", label="api.py", source_file="pkg/api.py")
    G.add_node("core", label="core.py", source_file="pkg/core.py")
    G.add_node("util", label="util.py", source_file="pkg/util.py")
    G.add_node("other", label="other.py", source_file="pkg/other.py")
    G.add_node("tcore", label="test_core.py", source_file="tests/test_core.py")
    G.add_edge("api", "core", relation="imports_from")
    G.add_edge("core", "util", relation="imports_from")
    G.add_edge("tcore", "core", relation="imports_from")
    return G


# ── slicing ───────────────────────────────────────────────────────────────────

def test_slice_walks_import_closure_and_skips_unrelated():
    sl = slice_files(_graph(), ["pkg/api.py"], depth=2)
    assert sl.files == ["pkg/api.py", "pkg/core.py", "pkg/util.py"]
    assert "pkg/other.py" not in sl.files


def test_slice_depth_bounds_closure():
    sl = slice_files(_graph(), ["pkg/api.py"], depth=1)
    assert sl.files == ["pkg/api.py", "pkg/core.py"]


def test_slice_accepts_symbol_target():
    sl = slice_files(_graph(), ["core.py"], depth=1)
    assert sl.files[0] == "pkg/core.py"


def test_slice_finds_graph_selected_tests():
    sl = slice_files(_graph(), ["pkg/api.py"], depth=2)
    assert sl.tests == ["tests/test_core.py"]


def test_tests_do_not_enter_the_code_closure():
    sl = slice_files(_graph(), ["pkg/core.py"], depth=3)
    assert all("test" not in f for f in sl.files)


def test_slice_unresolvable_target_raises():
    with pytest.raises(ValueError, match="cannot resolve"):
        slice_files(_graph(), ["ghost_target.py"])
    with pytest.raises(ValueError):
        slice_files(_graph(), [])


def test_tests_for_reverse_lookup():
    assert _tests_for(_graph(), {"pkg/core.py"}) == ["tests/test_core.py"]
    assert _tests_for(_graph(), {"pkg/other.py"}) == []


# ── materialization ───────────────────────────────────────────────────────────

def test_materialize_copies_structure_and_creates_init(tmp_path):
    repo = _repo(tmp_path)
    (repo / "pkg" / "__init__.py").unlink()  # force auto-creation
    sandbox = tmp_path / "box"
    placed = materialize(repo, ["pkg/core.py", "pkg/util.py"], sandbox)
    assert set(placed) == {"pkg/core.py", "pkg/util.py"}
    assert (sandbox / "pkg" / "__init__.py").exists()
    assert (sandbox / "pkg" / "core.py").read_text(encoding="utf-8").startswith("from pkg.util")


def test_materialize_prefers_real_init_when_repo_has_one(tmp_path):
    repo = _repo(tmp_path)
    (repo / "pkg" / "__init__.py").write_text("MARKER = 1\n", encoding="utf-8")
    sandbox = tmp_path / "box"
    materialize(repo, ["pkg/util.py"], sandbox)
    assert "MARKER" in (sandbox / "pkg" / "__init__.py").read_text(encoding="utf-8")


def test_materialize_injects_draft_over_file(tmp_path):
    repo = _repo(tmp_path)
    sandbox = tmp_path / "box"
    materialize(repo, ["pkg/core.py"], sandbox,
                draft_code="BROKEN(\n", draft_at="pkg/core.py")
    assert (sandbox / "pkg" / "core.py").read_text(encoding="utf-8") == "BROKEN(\n"


# ── real execution ────────────────────────────────────────────────────────────

def test_smoke_passes_on_healthy_slice(tmp_path):
    repo = _repo(tmp_path)
    sandbox = tmp_path / "box"
    files = ["pkg/api.py", "pkg/core.py", "pkg/util.py"]
    materialize(repo, files, sandbox)
    result = run_smoke(sandbox, files)
    assert result.ok, result.detail
    assert "OK pkg.api" in result.detail


def test_smoke_fails_with_real_traceback_on_poisoned_draft(tmp_path):
    repo = _repo(tmp_path)
    sandbox = tmp_path / "box"
    files = ["pkg/api.py", "pkg/core.py", "pkg/util.py"]
    materialize(repo, files, sandbox,
                draft_code="from pkg.util import doubler\n", draft_at="pkg/core.py")
    result = run_smoke(sandbox, files)
    assert not result.ok
    assert "FAIL pkg.core" in result.detail
    assert "ImportError" in result.detail or "cannot import" in result.detail


def test_run_tests_really_runs_pytest(tmp_path):
    repo = _repo(tmp_path)
    sandbox = tmp_path / "box"
    materialize(repo, ["pkg/api.py", "pkg/core.py", "pkg/util.py", "tests/test_core.py"], sandbox)
    result = run_tests(sandbox, ["tests/test_core.py"])
    assert result.ok, result.detail
    assert "1 passed" in result.detail


def test_run_tests_catches_regression_from_draft(tmp_path):
    repo = _repo(tmp_path)
    sandbox = tmp_path / "box"
    materialize(
        repo, ["pkg/api.py", "pkg/core.py", "pkg/util.py", "tests/test_core.py"], sandbox,
        draft_code="from pkg.util import double\n\ndef compute(x):\n    return double(x) - 1\n",
        draft_at="pkg/core.py",
    )
    result = run_tests(sandbox, ["tests/test_core.py"])
    assert not result.ok
    assert "1 failed" in result.detail


def test_run_tests_no_selected_tests_is_ok(tmp_path):
    assert run_tests(tmp_path, []).ok


# ── orchestration ─────────────────────────────────────────────────────────────

def test_wind_tunnel_end_to_end_pass(tmp_path):
    report = wind_tunnel(_graph(), _repo(tmp_path), ["pkg/api.py"])
    assert report["ok"] is True
    names = [p["name"] for p in report["phases"]]
    assert names == ["smoke", "tests"]
    assert not Path(report["sandbox"]).exists()  # cleaned up


def test_wind_tunnel_poisoned_draft_fails_and_skips_tests(tmp_path):
    report = wind_tunnel(
        _graph(), _repo(tmp_path), ["pkg/api.py"],
        draft_code="import nonexistent_ghost_pkg\n", draft_at="pkg/core.py",
    )
    assert report["ok"] is False
    assert [p["name"] for p in report["phases"]] == ["smoke"]  # tests skipped


def test_wind_tunnel_keep_preserves_sandbox(tmp_path):
    report = wind_tunnel(
        _graph(), _repo(tmp_path), ["pkg/util.py"], with_tests=False,
        sandbox_dir=tmp_path / "kept", keep=True,
    )
    assert Path(report["sandbox"]).exists()


def test_render_report_shapes(tmp_path):
    report = wind_tunnel(
        _graph(), _repo(tmp_path), ["pkg/api.py"],
        draft_code="BROKEN(\n", draft_at="pkg/core.py",
    )
    text = render_report(report)
    assert "[XX] wind tunnel" in text
    assert "smoke" in text
