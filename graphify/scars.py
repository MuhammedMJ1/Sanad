# Scar tissue: mine the repo's git history into mechanical warnings.
#
# A codebase's git log is a documented graveyard of mistakes: edits that were
# reverted, hotfixes that chased a change, file pairs that always move
# together. This module digs that history out ONCE (pure git, local, no LLM)
# and persists it as a sidecar next to graph.json, so every Sanad surface can
# warn BEFORE an edit:
#
#   - danger score per file: how often past edits here needed a fix/revert
#   - co-change couples: "files that changed with this one X% of the time"
#   - warnings for a planned edit set: "you are touching A without B, but
#     87% of past A-edits also touched B"
#
# This is senior-engineer instinct, injected mechanically. Even a frontier
# model cold-starting on the repo does not have this information.
from __future__ import annotations

import json
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

SCARS_FILENAME = ".graphify_scars.json"

# History window and noise guards. A bulk commit (format sweep, vendored drop,
# mass rename) would fabricate thousands of fake couples, so it is skipped for
# coupling (its files still count as edits).
MAX_COMMITS = 5000
MAX_FILES_PER_COMMIT = 50

# A couple must recur to mean anything: at least MIN_SUPPORT shared commits,
# and the partner must appear in at least MIN_CONFIDENCE of the file's edits.
MIN_SUPPORT = 3
MIN_CONFIDENCE = 0.5
MAX_COUPLES_PER_FILE = 8

_FIX_RE = re.compile(r"(?:^|[(\s:])fix(?:es|ed|up)?\b|\bhotfix\b|\bbugfix\b", re.IGNORECASE)
_REVERT_RE = re.compile(r"\brevert(?:s|ed)?\b|^Revert\b", re.IGNORECASE)

# Files that co-change with everything and mean nothing (locks, changelogs).
_NOISE_BASENAMES = {
    "changelog.md", "uv.lock", "package-lock.json", "yarn.lock", "poetry.lock",
    "cargo.lock", "gemfile.lock", "pnpm-lock.yaml", "composer.lock", "go.sum",
}


@dataclass
class FileScar:
    path: str
    edits: int = 0
    fix_edits: int = 0        # edits made by fix-flavored commits
    revert_edits: int = 0     # edits made by revert-flavored commits
    couples: list[dict] = field(default_factory=list)  # {path, support, confidence}

    @property
    def danger(self) -> float:
        """0..1: share of this file's edits that were fixes/reverts (reverts
        weigh double — an undone change is stronger evidence than a follow-up
        fix). Files with trivial history can't earn a high score."""
        if self.edits < 3:
            return 0.0
        weighted = self.fix_edits + 2 * self.revert_edits
        return round(min(1.0, weighted / self.edits), 3)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "edits": self.edits,
            "fix_edits": self.fix_edits,
            "revert_edits": self.revert_edits,
            "danger": self.danger,
            "couples": self.couples,
        }


def _git_log(repo_root: Path, max_commits: int) -> str:
    """Raw `git log` with file names; empty string when git/history is absent."""
    try:
        r = subprocess.run(
            ["git", "log", "--no-merges", "--name-only",
             f"--max-count={max_commits}", "--pretty=format:%x01%H%x02%s"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            cwd=repo_root, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if r.returncode != 0:
        return ""
    return r.stdout or ""


def _parse_commits(raw: str) -> list[tuple[str, list[str]]]:
    """[(subject, [files]), ...] from the \\x01-framed log output."""
    commits: list[tuple[str, list[str]]] = []
    for block in raw.split("\x01"):
        block = block.strip()
        if not block:
            continue
        head, _, body = block.partition("\n")
        _sha, _, subject = head.partition("\x02")
        files = [
            ln.strip().replace("\\", "/")
            for ln in body.splitlines()
            if ln.strip()
        ]
        commits.append((subject.strip(), files))
    return commits


def _is_noise(path: str) -> bool:
    return Path(path).name.lower() in _NOISE_BASENAMES


def mine_scars(
    repo_root: Path,
    *,
    max_commits: int = MAX_COMMITS,
    min_support: int = MIN_SUPPORT,
    min_confidence: float = MIN_CONFIDENCE,
) -> dict:
    """Mine git history into the scars mapping. Returns the sidecar dict.

    Deterministic and LLM-free. Returns an empty mapping (not an error) when
    the directory has no usable git history — scars are an enhancement, never
    a requirement.
    """
    raw = _git_log(Path(repo_root), max_commits)
    commits = _parse_commits(raw)

    edits: dict[str, int] = defaultdict(int)
    fixes: dict[str, int] = defaultdict(int)
    reverts: dict[str, int] = defaultdict(int)
    pair_counts: dict[tuple[str, str], int] = defaultdict(int)

    for subject, files in commits:
        files = [f for f in files if not _is_noise(f)]
        if not files:
            continue
        is_fix = bool(_FIX_RE.search(subject))
        is_revert = bool(_REVERT_RE.search(subject))
        for f in files:
            edits[f] += 1
            if is_revert:
                reverts[f] += 1
            elif is_fix:
                fixes[f] += 1
        # Coupling: skip bulk commits — they fabricate meaningless pairs.
        if 2 <= len(files) <= MAX_FILES_PER_COMMIT:
            uniq = sorted(set(files))
            for i, a in enumerate(uniq):
                for b in uniq[i + 1:]:
                    pair_counts[(a, b)] += 1

    scars: dict[str, FileScar] = {}
    for f, n in edits.items():
        scars[f] = FileScar(path=f, edits=n, fix_edits=fixes.get(f, 0),
                            revert_edits=reverts.get(f, 0))

    partners: dict[str, list[dict]] = defaultdict(list)
    for (a, b), support in pair_counts.items():
        if support < min_support:
            continue
        conf_a = support / edits[a] if edits[a] else 0.0
        conf_b = support / edits[b] if edits[b] else 0.0
        if conf_a >= min_confidence:
            partners[a].append({"path": b, "support": support, "confidence": round(conf_a, 3)})
        if conf_b >= min_confidence:
            partners[b].append({"path": a, "support": support, "confidence": round(conf_b, 3)})
    for f, plist in partners.items():
        plist.sort(key=lambda p: (-p["confidence"], -p["support"], p["path"]))
        if f in scars:
            scars[f].couples = plist[:MAX_COUPLES_PER_FILE]

    return {
        "version": 1,
        "commits_scanned": len(commits),
        "min_support": min_support,
        "min_confidence": min_confidence,
        "files": {f: s.to_dict() for f, s in scars.items()},
    }


def save_scars(out_dir: Path, data: dict) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / SCARS_FILENAME
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return p


def load_scars(out_dir: Path) -> dict | None:
    p = Path(out_dir) / SCARS_FILENAME
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and isinstance(data.get("files"), dict) else None


def _norm(path: str) -> str:
    return str(path).replace("\\", "/").lstrip("./")


def file_entry(data: dict, path: str) -> dict | None:
    """Look up one file's scar entry, tolerating path-prefix differences."""
    files = data.get("files", {})
    p = _norm(path)
    if p in files:
        return files[p]
    # Suffix match: graph paths may be repo-relative while scars are, or vice
    # versa ("graphify/cli.py" vs "cli.py"). Unique suffix wins; ambiguity loses.
    hits = [v for k, v in files.items() if k.endswith("/" + p) or p.endswith("/" + k)]
    return hits[0] if len(hits) == 1 else None


# ── warning generation ────────────────────────────────────────────────────────

DANGER_WARN = 0.30   # a third of past edits needed a fix/revert → say so


def warnings_for_edit(data: dict, planned_files: list[str]) -> list[str]:
    """Mechanical pre-edit warnings for a planned set of files.

    Two kinds:
    - danger: the file's own history says edits here frequently went wrong
    - missing partner: a strong historical co-change partner is NOT in the
      planned set — the classic source of half-done changes
    """
    planned = {_norm(f) for f in planned_files}
    out: list[str] = []
    for f in sorted(planned):
        entry = file_entry(data, f)
        if not entry:
            continue
        danger = float(entry.get("danger") or 0.0)
        if danger >= DANGER_WARN:
            out.append(
                f"[scar] {f}: {int(round(danger * 100))}% of its {entry.get('edits', 0)} "
                f"past edits needed a follow-up fix or revert — treat with care"
            )
        for couple in entry.get("couples", []):
            partner = _norm(str(couple.get("path", "")))
            if not partner or partner in planned:
                continue
            conf = float(couple.get("confidence") or 0.0)
            out.append(
                f"[scar] {f}: historically co-changes with {partner} "
                f"({int(round(conf * 100))}% of edits, {couple.get('support', 0)}x) "
                f"which is NOT in this change — check whether it needs the same edit"
            )
    return out


def render_file_report(data: dict, path: str) -> str:
    entry = file_entry(data, path)
    if not entry:
        return f"no scar history for {path} (new file, or outside the scanned window)"
    lines = [
        f"{entry['path']}: {entry.get('edits', 0)} edit(s), "
        f"{entry.get('fix_edits', 0)} fix(es), {entry.get('revert_edits', 0)} revert(s), "
        f"danger {entry.get('danger', 0.0)}"
    ]
    couples = entry.get("couples", [])
    if couples:
        lines.append("co-change partners:")
        for c in couples:
            lines.append(
                f"  - {c['path']} ({int(round(float(c['confidence']) * 100))}% of edits, {c['support']}x)"
            )
    else:
        lines.append("no strong co-change partners")
    return "\n".join(lines)


def render_summary(data: dict, *, top: int = 10) -> str:
    files = data.get("files", {})
    dangerous = sorted(
        (e for e in files.values() if float(e.get("danger") or 0) > 0),
        key=lambda e: (-float(e["danger"]), -int(e.get("edits", 0))),
    )[:top]
    coupled = sorted(
        (e for e in files.values() if e.get("couples")),
        key=lambda e: -float(e["couples"][0]["confidence"]),
    )[:top]
    lines = [
        f"scars: {len(files)} file(s) scanned across {data.get('commits_scanned', 0)} commit(s)",
    ]
    if dangerous:
        lines.append("most burn-prone files:")
        for e in dangerous:
            lines.append(
                f"  - {e['path']}  danger {e['danger']} "
                f"({e.get('fix_edits', 0)} fixes / {e.get('revert_edits', 0)} reverts "
                f"in {e.get('edits', 0)} edits)"
            )
    if coupled:
        lines.append("tightest co-change couples:")
        for e in coupled:
            c = e["couples"][0]
            lines.append(
                f"  - {e['path']} <-> {c['path']} "
                f"({int(round(float(c['confidence']) * 100))}%, {c['support']}x)"
            )
    if not dangerous and not coupled:
        lines.append("history too small for meaningful scars yet")
    return "\n".join(lines)
