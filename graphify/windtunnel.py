# Wind tunnel: real execution feedback for drafts, at near-zero cost.
#
# Big models "mentally simulate" what code will do; simulation hallucinates.
# The wind tunnel replaces imagination with reality: the graph knows the
# minimal set of project files a change actually touches, so we
#
#   1. SLICE      — walk import edges from the targets to the minimal closure,
#   2. MATERIALIZE — copy just those files into a scratch sandbox (package
#                    structure preserved, missing __init__.py filled in),
#                    optionally injecting a model's draft over one file,
#   3. RUN        — really import every sliced module (smoke) and really run
#                    the test files that historically import the slice,
#   4. REPORT     — a compact pass/fail with the first real traceback lines.
#
# Runs use the project's own interpreter (third-party deps resolve from the
# active environment); only the PROJECT files are sliced. Everything is
# subprocess-isolated with timeouts — a hanging draft cannot hang Sanad.
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from graphify.affected import resolve_seed

DEFAULT_DEPTH = 2
DEFAULT_TIMEOUT = 120  # seconds per phase
_REPORT_TAIL_LINES = 25

_DEP_RELATIONS = ("imports", "imports_from", "re_exports")


def _norm(path: str) -> str:
    return str(path).replace("\\", "/").lstrip("./")


def _is_test_file(path: str) -> bool:
    name = Path(path).name
    return name.startswith("test_") or name.endswith("_test.py") or "/tests/" in f"/{path}"


def _file_dep_map(G: nx.Graph) -> dict[str, set[str]]:
    """file -> set of files it imports (project-internal only), collapsed from
    node-level import edges (works whether the endpoints are file nodes or
    symbol nodes — only their source_file matters)."""
    deps: dict[str, set[str]] = {}
    for u, v, d in G.edges(data=True):
        if str(d.get("relation") or "") not in _DEP_RELATIONS:
            continue
        fu = _norm(str(G.nodes[u].get("source_file") or ""))
        fv = _norm(str(G.nodes[v].get("source_file") or ""))
        if fu and fv and fu != fv and fu.endswith(".py") and fv.endswith(".py"):
            deps.setdefault(fu, set()).add(fv)
    return deps


@dataclass
class Slice:
    seeds: list[str]
    files: list[str]                 # closure, seeds first, deterministic order
    tests: list[str] = field(default_factory=list)


def slice_files(G: nx.Graph, targets: list[str], *, depth: int = DEFAULT_DEPTH) -> Slice:
    """Minimal file closure for the targets: each target (file path or symbol)
    plus everything it transitively imports, bounded by depth."""
    if not targets:
        raise ValueError("slice_files needs at least one target")
    seeds: list[str] = []
    for t in targets:
        seed_file: str | None = None
        tn = _norm(t)
        if tn.endswith(".py"):
            # accept a raw path if any node lives in it
            if any(_norm(str(d.get("source_file") or "")) == tn for _, d in G.nodes(data=True)):
                seed_file = tn
        if seed_file is None:
            nid = resolve_seed(G, t)
            if nid is not None:
                seed_file = _norm(str(G.nodes[nid].get("source_file") or ""))
        if not seed_file or not seed_file.endswith(".py"):
            raise ValueError(f"cannot resolve {t!r} to a Python file in the graph")
        if seed_file not in seeds:
            seeds.append(seed_file)

    deps = _file_dep_map(G)
    closure: list[str] = list(seeds)
    seen = set(seeds)
    frontier = list(seeds)
    for _ in range(max(0, depth)):
        nxt: list[str] = []
        for f in frontier:
            for dep in sorted(deps.get(f, ())):
                if dep not in seen and not _is_test_file(dep):
                    seen.add(dep)
                    closure.append(dep)
                    nxt.append(dep)
        frontier = nxt
        if not frontier:
            break

    tests = tests_for(G, set(closure), deps=deps)
    return Slice(seeds=seeds, files=closure, tests=tests)


def tests_for(G: nx.Graph, files: set[str], *, deps: dict[str, set[str]] | None = None) -> list[str]:
    """Test files that import anything in `files` — the graph-selected suite."""
    deps = deps if deps is not None else _file_dep_map(G)
    out = sorted(
        t for t, imported in deps.items()
        if _is_test_file(t) and imported & files
    )
    return out


# ── sandbox ───────────────────────────────────────────────────────────────────

def materialize(
    repo_root: Path,
    files: list[str],
    sandbox: Path,
    *,
    draft_code: str | None = None,
    draft_at: str | None = None,
) -> list[str]:
    """Copy the slice into `sandbox` (structure preserved), create missing
    package __init__.py files, and optionally lay a draft over one path.
    Returns the repo-relative paths that ended up in the sandbox."""
    placed: list[str] = []
    wanted = list(files)
    if draft_at:
        da = _norm(draft_at)
        if da not in wanted:
            wanted.append(da)
    for rel in wanted:
        dst = sandbox / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        src = repo_root / rel
        if draft_at and _norm(rel) == _norm(draft_at):
            dst.write_text(draft_code or "", encoding="utf-8")
        elif src.exists():
            shutil.copyfile(src, dst)
        else:
            continue
        placed.append(rel)
        # package chain: pkg/sub/mod.py needs pkg/__init__.py and pkg/sub/__init__.py
        parent = dst.parent
        while parent != sandbox:
            init = parent / "__init__.py"
            if not init.exists():
                init_src = repo_root / init.relative_to(sandbox)
                if init_src.exists():
                    shutil.copyfile(init_src, init)
                else:
                    init.write_text("", encoding="utf-8")
            parent = parent.parent
    return placed


def _module_name(rel: str) -> str:
    return _norm(rel)[:-3].replace("/", ".")


_SMOKE_RUNNER = """\
import importlib, sys, traceback
failed = 0
for mod in sys.argv[1:]:
    try:
        importlib.import_module(mod)
        print("OK " + mod)
    except BaseException:
        failed += 1
        print("FAIL " + mod)
        tb = traceback.format_exc().strip().splitlines()
        for line in tb[-4:]:
            print("    " + line)
sys.exit(1 if failed else 0)
"""


@dataclass
class PhaseResult:
    name: str
    ok: bool
    seconds: float
    detail: str = ""


def run_smoke(sandbox: Path, files: list[str], *, python_exe: str | None = None,
              timeout: int = DEFAULT_TIMEOUT) -> PhaseResult:
    """Really import every sliced module inside the sandbox."""
    mods = [_module_name(f) for f in files if f.endswith(".py") and not _is_test_file(f)]
    if not mods:
        return PhaseResult("smoke", True, 0.0, "nothing importable in the slice")
    runner = sandbox / "_sanad_smoke.py"
    runner.write_text(_SMOKE_RUNNER, encoding="utf-8")
    t0 = time.monotonic()
    try:
        r = subprocess.run(
            [python_exe or sys.executable, str(runner), *mods],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            cwd=sandbox, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return PhaseResult("smoke", False, time.monotonic() - t0,
                           f"timed out after {timeout}s (hanging import?)")
    tail = "\n".join((r.stdout or "").strip().splitlines()[-_REPORT_TAIL_LINES:])
    return PhaseResult("smoke", r.returncode == 0, time.monotonic() - t0, tail)


def run_tests(sandbox: Path, test_files: list[str], *, python_exe: str | None = None,
              timeout: int = DEFAULT_TIMEOUT) -> PhaseResult:
    """Really run the graph-selected tests inside the sandbox."""
    present = [t for t in test_files if (sandbox / t).exists()]
    if not present:
        return PhaseResult("tests", True, 0.0, "no graph-selected tests in the slice")
    t0 = time.monotonic()
    try:
        r = subprocess.run(
            [python_exe or sys.executable, "-m", "pytest", "-q", "-x", "--no-header",
             "-p", "no:cacheprovider", *present],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            cwd=sandbox, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return PhaseResult("tests", False, time.monotonic() - t0,
                           f"timed out after {timeout}s")
    out = ((r.stdout or "") + "\n" + (r.stderr or "")).strip()
    tail = "\n".join(out.splitlines()[-_REPORT_TAIL_LINES:])
    return PhaseResult("tests", r.returncode == 0, time.monotonic() - t0, tail)


# ── orchestration ─────────────────────────────────────────────────────────────

def wind_tunnel(
    G: nx.Graph,
    repo_root: Path,
    targets: list[str],
    *,
    draft_code: str | None = None,
    draft_at: str | None = None,
    depth: int = DEFAULT_DEPTH,
    with_tests: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    python_exe: str | None = None,
    sandbox_dir: Path | None = None,
    keep: bool = False,
) -> dict:
    """Slice, materialize, and really run. Returns the report dict."""
    sl = slice_files(G, targets, depth=depth)
    sandbox = Path(sandbox_dir) if sandbox_dir else Path(tempfile.mkdtemp(prefix="sanad-tunnel-"))
    sandbox.mkdir(parents=True, exist_ok=True)
    try:
        to_place = list(sl.files) + (sl.tests if with_tests else [])
        placed = materialize(repo_root, to_place, sandbox,
                             draft_code=draft_code, draft_at=draft_at)
        phases: list[PhaseResult] = []
        smoke_files = sl.files + ([draft_at] if draft_at and draft_at not in sl.files else [])
        phases.append(run_smoke(sandbox, smoke_files, python_exe=python_exe, timeout=timeout))
        # A slice that cannot even import makes test results pure noise.
        if with_tests and phases[-1].ok:
            phases.append(run_tests(sandbox, sl.tests, python_exe=python_exe, timeout=timeout))
        ok = all(p.ok for p in phases)
        return {
            "ok": ok,
            "seeds": sl.seeds,
            "sliced_files": sl.files,
            "tests": sl.tests if with_tests else [],
            "placed": placed,
            "sandbox": str(sandbox),
            "kept": keep,
            "phases": [
                {"name": p.name, "ok": p.ok, "seconds": round(p.seconds, 2), "detail": p.detail}
                for p in phases
            ],
        }
    finally:
        if not keep:
            shutil.rmtree(sandbox, ignore_errors=True)


def render_report(report: dict) -> str:
    lines: list[str] = []
    mark = "[ok]" if report["ok"] else "[XX]"
    lines.append(
        f"{mark} wind tunnel: {len(report['sliced_files'])} file(s) sliced, "
        f"{len(report['tests'])} graph-selected test file(s)"
    )
    for p in report["phases"]:
        pm = "[ok]" if p["ok"] else "[XX]"
        lines.append(f"  {pm} {p['name']} ({p['seconds']}s)")
        if p["detail"] and (not p["ok"] or p["name"] == "smoke"):
            for ln in p["detail"].splitlines():
                lines.append(f"      {ln}")
    if report.get("kept"):
        lines.append(f"  sandbox kept at: {report['sandbox']}")
    return "\n".join(lines)
