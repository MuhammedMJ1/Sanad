"""Tests for scars.py - git-history scar mining.

A scripted throwaway git repo provides controlled history: api.py and
schema.py always change together, risky.py keeps needing fixes/reverts,
solo.py changes alone. The miner must surface the couple and the danger,
warnings must fire for a planned edit that forgets the partner, and the
sidecar must round-trip.
"""
import json
import subprocess
from pathlib import Path

import pytest

from graphify.scars import (
    DANGER_WARN,
    SCARS_FILENAME,
    FileScar,
    file_entry,
    load_scars,
    mine_scars,
    render_file_report,
    render_summary,
    save_scars,
    warnings_for_edit,
)


def _git(repo: Path, *args: str) -> None:
    r = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, timeout=60
    )
    assert r.returncode == 0, f"git {args} failed: {r.stderr}"


def _commit(repo: Path, subject: str, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", subject)


@pytest.fixture()
def history_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    n = 0
    # api.py + schema.py co-change 5 times (couple: support 5).
    for i in range(5):
        _commit(repo, f"feat: endpoint {i}", {"api.py": f"a{i}", "schema.py": f"s{i}"})
        n += 1
    # api.py once alone -> confidence 5/6.
    _commit(repo, "feat: api-only tweak", {"api.py": "solo"})
    # risky.py: 2 normal edits, 2 fixes, 1 revert -> danger (2+2*1)/5 = 0.8.
    _commit(repo, "feat: add risky", {"risky.py": "r0"})
    _commit(repo, "feat: extend risky", {"risky.py": "r1"})
    _commit(repo, "fix: risky crash on empty input", {"risky.py": "r2"})
    _commit(repo, "fix: risky again", {"risky.py": "r3"})
    _commit(repo, 'Revert "feat: extend risky"', {"risky.py": "r4"})
    # solo.py: quiet single edit, no scars.
    _commit(repo, "docs: add solo", {"solo.py": "x"})
    return repo


# ── mining ────────────────────────────────────────────────────────────────────

def test_couple_detected_with_support_and_confidence(history_repo):
    data = mine_scars(history_repo)
    api = data["files"]["api.py"]
    assert api["edits"] == 6
    couple = next(c for c in api["couples"] if c["path"] == "schema.py")
    assert couple["support"] == 5
    assert couple["confidence"] == pytest.approx(5 / 6, abs=0.01)
    # symmetric: schema.py couples back at 100%
    schema = data["files"]["schema.py"]
    back = next(c for c in schema["couples"] if c["path"] == "api.py")
    assert back["confidence"] == 1.0


def test_danger_score_counts_fixes_and_reverts_double(history_repo):
    data = mine_scars(history_repo)
    risky = data["files"]["risky.py"]
    assert risky["edits"] == 5
    assert risky["fix_edits"] == 2
    assert risky["revert_edits"] == 1
    assert risky["danger"] == pytest.approx(0.8)


def test_quiet_file_has_no_scars(history_repo):
    data = mine_scars(history_repo)
    solo = data["files"]["solo.py"]
    assert solo["danger"] == 0.0
    assert solo["couples"] == []


def test_min_support_threshold_prunes_weak_couples(history_repo):
    data = mine_scars(history_repo, min_support=6)
    assert data["files"]["api.py"]["couples"] == []


def test_min_confidence_threshold(history_repo):
    # api.py confidence is 5/6 ≈ 0.83; a 0.9 floor prunes it.
    data = mine_scars(history_repo, min_confidence=0.9)
    assert all(c["path"] != "schema.py" for c in data["files"]["api.py"]["couples"])
    # schema.py side is 5/5 = 1.0 and survives.
    assert any(c["path"] == "api.py" for c in data["files"]["schema.py"]["couples"])


def test_no_git_repo_returns_empty_mapping(tmp_path):
    data = mine_scars(tmp_path / "not_a_repo_dir")
    assert data["files"] == {}
    assert data["commits_scanned"] == 0


def test_danger_needs_minimum_history():
    s = FileScar(path="x.py", edits=2, fix_edits=2)
    assert s.danger == 0.0  # 2 edits is not evidence, it's noise


# ── warnings ──────────────────────────────────────────────────────────────────

def test_warning_fires_when_partner_missing(history_repo):
    data = mine_scars(history_repo)
    warns = warnings_for_edit(data, ["api.py"])
    assert any("schema.py" in w and "NOT in this change" in w for w in warns)


def test_no_partner_warning_when_both_planned(history_repo):
    data = mine_scars(history_repo)
    warns = warnings_for_edit(data, ["api.py", "schema.py"])
    assert not any("NOT in this change" in w for w in warns)


def test_danger_warning_fires_above_threshold(history_repo):
    data = mine_scars(history_repo)
    warns = warnings_for_edit(data, ["risky.py"])
    assert any("follow-up fix or revert" in w for w in warns)
    assert DANGER_WARN < 0.8


def test_clean_file_produces_no_warnings(history_repo):
    data = mine_scars(history_repo)
    assert warnings_for_edit(data, ["solo.py"]) == []


# ── sidecar persistence + lookup ─────────────────────────────────────────────

def test_sidecar_round_trip(history_repo, tmp_path):
    data = mine_scars(history_repo)
    out = tmp_path / "graphify-out"
    p = save_scars(out, data)
    assert p.name == SCARS_FILENAME
    loaded = load_scars(out)
    assert loaded is not None
    assert loaded["files"]["risky.py"]["danger"] == pytest.approx(0.8)


def test_load_scars_missing_or_corrupt(tmp_path):
    assert load_scars(tmp_path) is None
    (tmp_path / SCARS_FILENAME).write_text("{broken", encoding="utf-8")
    assert load_scars(tmp_path) is None


def test_file_entry_suffix_matching(history_repo):
    data = mine_scars(history_repo)
    # graph-side paths can carry a repo prefix; unique suffix must resolve.
    data["files"]["src/deep/thing.py"] = data["files"].pop("solo.py")
    assert file_entry(data, "thing.py") is not None
    assert file_entry(data, "deep/thing.py") is not None
    assert file_entry(data, "nowhere.py") is None


# ── rendering ─────────────────────────────────────────────────────────────────

def test_render_file_report_and_summary(history_repo):
    data = mine_scars(history_repo)
    rep = render_file_report(data, "api.py")
    assert "schema.py" in rep and "co-change partners" in rep
    summary = render_summary(data)
    assert "risky.py" in summary  # most burn-prone
    assert "api.py" in summary or "schema.py" in summary
    assert render_file_report(data, "ghost.py").startswith("no scar history")
