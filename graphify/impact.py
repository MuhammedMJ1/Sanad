# Edit blast-radius oracle: predict which parts of the codebase an edit will
# touch BEFORE the edit, then hold the edit to that prediction AFTER it.
#
# Flow (predict -> edit -> check):
#   1. `graphify predict <targets...>` walks reverse dependencies from the
#      edit targets (via affected.py) and writes an impact contract plus a
#      baseline snapshot of graph.json.
#   2. The agent edits code and refreshes the graph (`graphify update .`).
#   3. `graphify check-impact` diffs baseline vs current graph per file: a
#      changed file OUTSIDE the contract means the edit rippled somewhere the
#      model never predicted — the classic "I understood this change" lie —
#      and is reported as a DEVIATION.
from __future__ import annotations

import json
import shutil
from pathlib import Path

import networkx as nx

from graphify.affected import (
    DEFAULT_AFFECTED_RELATIONS,
    affected_nodes,
    load_graph,
    resolve_seed,
)

CONTRACT_FILENAME = ".graphify_impact_contract.json"
BASELINE_FILENAME = ".graphify_impact_baseline.json"

DEFAULT_DEPTH = 2

# Deviation verdicts.
CLEAN = "CLEAN"            # every changed file was predicted (or is an edit target)
DEVIATION = "DEVIATION"    # at least one changed file fell outside the contract
NO_CHANGES = "NO_CHANGES"  # baseline and current graph are identical


def _norm_file(path: str | None) -> str:
    return (path or "").replace("\\", "/")


def _node_file(data: dict) -> str:
    return _norm_file(str(data.get("source_file") or ""))


def predict_impact(
    G: nx.Graph,
    targets: list[str],
    *,
    depth: int = DEFAULT_DEPTH,
) -> dict:
    """Predict the blast radius of editing ``targets`` (files or symbols).

    Returns the contract dict. Raises ValueError when a target does not
    resolve to a unique node — an oracle anchored on the wrong node would
    produce a confidently wrong prediction, which is worse than no answer.
    """
    if not targets:
        raise ValueError("predict_impact needs at least one target")

    resolved: list[dict] = []
    predicted: list[dict] = []
    predicted_files: set[str] = set()
    seen_nodes: set[str] = set()

    for target in targets:
        seed = resolve_seed(G, target)
        if seed is None:
            raise ValueError(
                f"no unique node match for {target!r} — use a more specific "
                f"label, a source file path, or the exact node id"
            )
        seed_data = G.nodes[seed]
        seed_file = _node_file(seed_data)
        resolved.append({
            "query": target,
            "node_id": str(seed),
            "label": str(seed_data.get("label") or seed),
            "source_file": seed_file,
        })
        if seed_file:
            predicted_files.add(seed_file)
        for hit in affected_nodes(G, seed, relations=DEFAULT_AFFECTED_RELATIONS, depth=depth):
            if hit.node_id in seen_nodes:
                continue
            seen_nodes.add(hit.node_id)
            data = G.nodes[hit.node_id]
            f = _node_file(data)
            predicted.append({
                "node_id": str(hit.node_id),
                "label": str(data.get("label") or hit.node_id),
                "source_file": f,
                "depth": hit.depth,
                "via_relation": hit.via_relation,
            })
            if f:
                predicted_files.add(f)

    return {
        "version": 1,
        "targets": resolved,
        "depth": depth,
        "predicted_nodes": predicted,
        "predicted_files": sorted(predicted_files),
    }


def write_contract(out_dir: Path, contract: dict, graph_path: Path) -> Path:
    """Persist the contract and snapshot graph.json as the diff baseline."""
    out_dir.mkdir(parents=True, exist_ok=True)
    contract_path = out_dir / CONTRACT_FILENAME
    contract_path.write_text(
        json.dumps(contract, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    shutil.copyfile(graph_path, out_dir / BASELINE_FILENAME)
    return contract_path


def _file_fingerprints(G: nx.Graph) -> dict[str, set]:
    """Per-file fingerprint: the set of node ids plus (src, relation, tgt)
    edge triples owned by each file. A file "changed" iff its fingerprint
    differs between snapshots. Node ids are path-qualified and stable across
    rebuilds, so id-level diffing is exact, not heuristic."""
    fp: dict[str, set] = {}
    for nid, data in G.nodes(data=True):
        f = _node_file(data)
        if f:
            fp.setdefault(f, set()).add(("node", str(nid)))
    for u, v, data in G.edges(data=True):
        rel = str(data.get("relation") or "")
        for endpoint in (u, v):
            f = _node_file(G.nodes[endpoint])
            if f:
                fp.setdefault(f, set()).add(("edge", str(u), rel, str(v)))
    return fp


def diff_changed_files(old: nx.Graph, new: nx.Graph) -> list[str]:
    """Files whose node/edge fingerprint differs between the two snapshots."""
    old_fp = _file_fingerprints(old)
    new_fp = _file_fingerprints(new)
    changed = {
        f for f in set(old_fp) | set(new_fp)
        if old_fp.get(f, set()) != new_fp.get(f, set())
    }
    return sorted(changed)


def check_impact(contract: dict, old: nx.Graph, new: nx.Graph) -> dict:
    """Compare actual graph change against the predicted contract."""
    changed = diff_changed_files(old, new)
    target_files = {_norm_file(t.get("source_file")) for t in contract.get("targets", [])}
    target_files.discard("")
    predicted_files = {_norm_file(f) for f in contract.get("predicted_files", [])}
    allowed = predicted_files | target_files

    inside = [f for f in changed if f in allowed]
    outside = [f for f in changed if f not in allowed]
    predicted_untouched = sorted(allowed - set(changed))

    if not changed:
        verdict = NO_CHANGES
    elif outside:
        verdict = DEVIATION
    else:
        verdict = CLEAN
    return {
        "verdict": verdict,
        "changed_files": changed,
        "inside_contract": inside,
        "outside_contract": outside,
        "predicted_untouched": predicted_untouched,
    }


def load_contract(out_dir: Path) -> dict:
    contract_path = out_dir / CONTRACT_FILENAME
    if not contract_path.exists():
        raise FileNotFoundError(
            f"no impact contract at {contract_path} — run `graphify predict <target>` "
            f"before editing, then `graphify check-impact` after `graphify update .`"
        )
    return json.loads(contract_path.read_text(encoding="utf-8"))


def load_baseline(out_dir: Path) -> nx.Graph:
    baseline_path = out_dir / BASELINE_FILENAME
    if not baseline_path.exists():
        raise FileNotFoundError(
            f"no baseline snapshot at {baseline_path} — run `graphify predict` first"
        )
    return load_graph(baseline_path)


# ── rendering ─────────────────────────────────────────────────────────────────

def render_prediction(contract: dict) -> str:
    lines: list[str] = []
    tlabels = ", ".join(t["label"] for t in contract["targets"])
    lines.append(f"Impact prediction for: {tlabels} (depth {contract['depth']})")
    nodes = contract["predicted_nodes"]
    if not nodes:
        lines.append("No dependents found — the edit should be self-contained.")
    else:
        lines.append(f"{len(nodes)} dependent node(s) across "
                     f"{len(contract['predicted_files'])} file(s) may be affected:")
        by_file: dict[str, list[dict]] = {}
        for n in nodes:
            by_file.setdefault(n["source_file"] or "-", []).append(n)
        for f in sorted(by_file):
            lines.append(f"  {f}")
            for n in sorted(by_file[f], key=lambda x: (x["depth"], x["label"])):
                lines.append(f"    - {n['label']} [{n['via_relation']}, depth {n['depth']}]")
    lines.append("")
    lines.append("Contract saved. After editing, run `graphify update .` then "
                 "`graphify check-impact`.")
    return "\n".join(lines)


def render_check(report: dict) -> str:
    lines: list[str] = []
    v = report["verdict"]
    if v == NO_CHANGES:
        lines.append("[ok] NO_CHANGES: the graph is identical to the baseline.")
    elif v == CLEAN:
        lines.append("[ok] CLEAN: every changed file was inside the predicted blast radius.")
    else:
        lines.append("[XX] DEVIATION: the edit changed files OUTSIDE the predicted blast radius.")
    if report["inside_contract"]:
        lines.append("  changed as predicted:")
        for f in report["inside_contract"]:
            lines.append(f"    - {f}")
    if report["outside_contract"]:
        lines.append("  changed but NOT predicted (review these):")
        for f in report["outside_contract"]:
            lines.append(f"    - {f}")
    return "\n".join(lines)
