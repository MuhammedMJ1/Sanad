# Hallucination gate: mechanically verify natural-language claims about a
# codebase against the deterministic knowledge graph in graph.json.
#
# The graph is built by tree-sitter AST extraction (no LLM), so it is ground
# truth for structural claims. A claim that cannot be backed by a node, edge,
# or bounded path in the graph is flagged instead of trusted — turning the
# graph into a pre-publication filter for LLM output about the codebase.
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from graphify.build import edge_data
from graphify.serve import _load_graph, _pick_scored_endpoint, _score_nodes, _search_tokens

# Verdict labels, strongest to weakest.
VERIFIED = "VERIFIED"                    # direct edge (or node/file fact) confirms the claim
VERIFIED_INDIRECT = "VERIFIED_INDIRECT"  # no direct edge, but a bounded path connects the endpoints
UNKNOWN = "UNKNOWN"                      # an endpoint didn't resolve (or resolved ambiguously)
REFUTED = "REFUTED"                      # both endpoints resolved confidently; graph shows no support

# A claim whose endpoints resolve but whose connection needs more hops than
# this is treated as unsupported: beyond a few hops everything in one codebase
# connects to everything, so "connected" stops meaning anything.
DEFAULT_MAX_HOPS = 3

# Resolution must be confident before a claim can be REFUTED (a mis-resolved
# label must fail safe to UNKNOWN, never to a false refutation). Confident =
# the picked node's label contains every query token, or the top score leads
# the runner-up by at least this margin.
_AMBIGUITY_MARGIN = 0.10

# relation synonyms the extractor may emit vs. what models commonly say.
_RELATION_ALIASES = {
    "call": "calls",
    "invokes": "calls",
    "invoke": "calls",
    "import": "imports",
    "imports_from": "imports",
    "use": "uses",
    "inherit": "inherits",
    "inherits_from": "inherits",
    "extends": "inherits",
    "subclasses": "inherits",
    "reference": "references",
    "refers_to": "references",
    "depends_on": "uses",
    "contain": "contains",
    "defines": "contains",
}


@dataclass
class Claim:
    """One checkable statement about the codebase.

    relation is a graph relation ("calls", "imports", ...) or a pseudo-relation:
    - "exists":      subject is a real node (object empty)
    - "defined_in":  subject's source_file matches object
    - "connected":   subject and object are connected at all (any relation)
    """

    subject: str
    relation: str
    object: str = ""
    raw: str = ""  # original sentence, for reporting

    def normalized_relation(self) -> str:
        rel = self.relation.strip().lower().replace(" ", "_")
        return _RELATION_ALIASES.get(rel, rel)


@dataclass
class Verdict:
    claim: Claim
    verdict: str
    evidence: str = ""
    confidence: str = ""          # EXTRACTED / INFERRED / AMBIGUOUS from the backing edge
    path: list[str] = field(default_factory=list)  # node labels of the proof path

    def to_dict(self) -> dict:
        return {
            "subject": self.claim.subject,
            "relation": self.claim.relation,
            "object": self.claim.object,
            "raw": self.claim.raw,
            "verdict": self.verdict,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "path": self.path,
        }


def load_graph(graph_path: str | Path) -> nx.Graph:
    """Load graph.json with the same guards the MCP server uses."""
    return _load_graph(str(graph_path))


# A label like `build_graph()` can name several real nodes (production code
# plus a test fixture, or one per language). Judging a claim on a single
# arbitrary winner produces false refutations, so claims are checked against
# every strong candidate and refuted only when ALL of them fail. Capped to
# bound the pair-product on very common labels.
_MAX_CANDIDATES = 8


def _resolve(G: nx.Graph, label: str) -> tuple[list[str], bool]:
    """Resolve a free-text label to candidate node ids.

    Returns (candidates, confident). Empty list means no match at all.
    candidates holds every full-token label match (up to _MAX_CANDIDATES),
    falling back to the best-scored node when none full-match. confident=False
    means resolution is too ambiguous for a claim to be REFUTED on.
    """
    terms = [t.lower() for t in label.split()]
    scored = _score_nodes(G, terms)
    if not scored:
        return [], False
    qtokens = set(_search_tokens(label))
    full_matches: list[str] = []
    if qtokens:
        for _score, nid in scored:
            if qtokens <= set(_search_tokens(G.nodes[nid].get("label") or nid)):
                full_matches.append(nid)
                if len(full_matches) >= _MAX_CANDIDATES:
                    break
    if full_matches:
        return full_matches, True
    nid = _pick_scored_endpoint(G, scored, label)
    if len(scored) >= 2 and nid == scored[0][1]:
        top, runner = scored[0][0], scored[1][0]
        if top > 0 and (top - runner) / top < _AMBIGUITY_MARGIN:
            return [nid], False
    return [nid], True


def _direct_edge(G: nx.Graph, src: str, tgt: str) -> dict | None:
    if G.has_edge(src, tgt):
        return dict(edge_data(G, src, tgt) or {})
    return None


def _label(G: nx.Graph, nid: str) -> str:
    return str(G.nodes[nid].get("label") or nid)


def _bounded_path(G: nx.Graph, src: str, tgt: str, max_hops: int) -> list[str] | None:
    """Shortest undirected path between src and tgt, if within max_hops."""
    try:
        nodes = nx.shortest_path(G.to_undirected(as_view=True), src, tgt)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None
    if len(nodes) - 1 > max_hops:
        return None
    return nodes


# Verdict strength for merging per-candidate outcomes: a claim is as true as
# its BEST-supported reading, and only REFUTED when every reading fails.
_RANK = {VERIFIED: 3, VERIFIED_INDIRECT: 2, UNKNOWN: 1, REFUTED: 0}


def _norm_relation(raw: str) -> str:
    rel = raw.strip().lower().replace(" ", "_")
    return _RELATION_ALIASES.get(rel, rel)


def _check_pair(
    G: nx.Graph, claim: Claim, rel: str, src_id: str, tgt_id: str,
    confident: bool, max_hops: int,
) -> Verdict:
    """Judge one (subject-candidate, object-candidate) reading of a claim."""
    src_l, tgt_l = _label(G, src_id), _label(G, tgt_id)

    # 1) Direct edge in the claimed direction. Both sides of the relation
    # comparison are alias-normalized so a stored "imports_from" satisfies a
    # claimed "imports".
    fwd = _direct_edge(G, src_id, tgt_id)
    if fwd is not None:
        actual = str(fwd.get("relation") or "")
        conf = str(fwd.get("confidence") or "")
        if rel == "connected" or _norm_relation(actual) == rel:
            return Verdict(claim, VERIFIED,
                           evidence=f"{src_l} --{actual}--> {tgt_l}",
                           confidence=conf, path=[src_l, tgt_l])
        # Edge exists but is named differently ("uses" vs "calls"): the
        # connection is real, so don't refute — report the actual relation.
        return Verdict(claim, VERIFIED_INDIRECT,
                       evidence=f"direct edge exists but relation is "
                                f"'{actual}', not '{rel}': {src_l} --{actual}--> {tgt_l}",
                       confidence=conf, path=[src_l, tgt_l])

    # 2) Edge exists only in the opposite direction: for directional relations
    # this is exactly the kind of subtle hallucination worth catching.
    rev = _direct_edge(G, tgt_id, src_id)
    if rev is not None:
        actual = str(rev.get("relation") or "")
        conf = str(rev.get("confidence") or "")
        if rel == "connected":
            return Verdict(claim, VERIFIED,
                           evidence=f"{tgt_l} --{actual}--> {src_l}",
                           confidence=conf, path=[src_l, tgt_l])
        if _norm_relation(actual) == rel and confident:
            return Verdict(claim, REFUTED,
                           evidence=f"direction is reversed: graph has "
                                    f"{tgt_l} --{actual}--> {src_l}",
                           confidence=conf, path=[tgt_l, src_l])
        return Verdict(claim, VERIFIED_INDIRECT,
                       evidence=f"reverse edge exists: {tgt_l} --{actual}--> {src_l}",
                       confidence=conf, path=[tgt_l, src_l])

    # 3) Bounded path.
    path_nodes = _bounded_path(G, src_id, tgt_id, max_hops)
    if path_nodes is not None:
        labels = [_label(G, n) for n in path_nodes]
        return Verdict(claim, VERIFIED_INDIRECT,
                       evidence=f"connected via {len(path_nodes) - 1} hop(s): "
                                + " -> ".join(labels),
                       path=labels)

    # 4) Nothing supports this reading.
    if confident:
        return Verdict(claim, REFUTED,
                       evidence=f"no edge and no path within {max_hops} hops between "
                                f"'{src_l}' and '{tgt_l}'")
    return Verdict(claim, UNKNOWN,
                   evidence=f"no connection found, but endpoint resolution was ambiguous "
                            f"('{claim.subject}' -> '{src_l}', '{claim.object}' -> '{tgt_l}')")


def check_claim(G: nx.Graph, claim: Claim, *, max_hops: int = DEFAULT_MAX_HOPS) -> Verdict:
    """Verify one claim against the graph.

    Labels may name several nodes (production symbol + a test fixture, one per
    language, ...). Every strong candidate reading is checked and the claim
    gets its best-supported verdict — REFUTED only when all readings fail.
    """
    rel = claim.normalized_relation()

    src_ids, src_conf = _resolve(G, claim.subject)
    if not src_ids:
        return Verdict(claim, UNKNOWN, evidence=f"'{claim.subject}' not found in the graph")

    if rel == "exists":
        nid = src_ids[0]
        return Verdict(
            claim, VERIFIED,
            evidence=f"node '{_label(G, nid)}' "
                     f"({G.nodes[nid].get('source_file') or 'no source'})",
        )

    if rel == "defined_in":
        want = claim.object.replace("\\", "/").lower().strip()
        if not want:
            return Verdict(claim, UNKNOWN, evidence="defined_in claim has no file")
        sources = []
        for nid in src_ids:
            got = str(G.nodes[nid].get("source_file") or "").replace("\\", "/")
            if not got:
                continue
            sources.append(got)
            if got.lower().endswith(want) or want.endswith(got.lower()) or want in got.lower():
                return Verdict(claim, VERIFIED, evidence=f"defined in {got}")
        if not sources:
            return Verdict(claim, UNKNOWN,
                           evidence=f"'{claim.subject}' has no source_file in the graph")
        if not src_conf:
            return Verdict(claim, UNKNOWN,
                           evidence=f"ambiguous subject; best match is defined in {sources[0]}")
        return Verdict(claim, REFUTED,
                       evidence=f"'{claim.subject}' is defined in {', '.join(sorted(set(sources)))}, "
                                f"not {claim.object}")

    if not claim.object:
        return Verdict(claim, UNKNOWN, evidence=f"relation '{claim.relation}' needs an object")

    tgt_ids, tgt_conf = _resolve(G, claim.object)
    if not tgt_ids:
        return Verdict(claim, UNKNOWN, evidence=f"'{claim.object}' not found in the graph")
    pairs = [(s, t) for s in src_ids for t in tgt_ids if s != t]
    if not pairs:
        return Verdict(claim, UNKNOWN,
                       evidence=f"'{claim.subject}' and '{claim.object}' resolve to the same node")

    confident = src_conf and tgt_conf
    best: Verdict | None = None
    for s, t in pairs:
        v = _check_pair(G, claim, rel, s, t, confident, max_hops)
        if best is None or _RANK[v.verdict] > _RANK[best.verdict]:
            best = v
        if best.verdict == VERIFIED:
            break
    return best


def check_claims(G: nx.Graph, claims: list[Claim], *, max_hops: int = DEFAULT_MAX_HOPS) -> list[Verdict]:
    return [check_claim(G, c, max_hops=max_hops) for c in claims]


# ── Plain-text claim extraction (deterministic, no LLM) ──────────────────────
# Conservative by design: only sentences with a backticked/CamelCase/snake_case
# identifier pair joined by a known relation verb become relation claims; every
# lone identifier becomes an "exists" claim. Precise callers should send
# structured JSON claims instead.

_RELATION_PATTERNS = [
    (re.compile(r"\bcalls?\b|\binvokes?\b", re.IGNORECASE), "calls"),
    (re.compile(r"\bimports?\b", re.IGNORECASE), "imports"),
    (re.compile(r"\binherits(?:\s+from)?\b|\bextends\b|\bsubclasses\b", re.IGNORECASE), "inherits"),
    (re.compile(r"\buses?\b|\bdepends\s+on\b", re.IGNORECASE), "uses"),
    (re.compile(r"\breferences?\b|\brefers\s+to\b", re.IGNORECASE), "references"),
    (re.compile(r"\bcontains?\b|\bdefines?\b", re.IGNORECASE), "contains"),
]
_DEFINED_IN_RE = re.compile(r"\b(?:defined|declared|implemented|located)\s+in\b", re.IGNORECASE)

# `code spans`, function() names, CamelCase, dotted.paths, snake_case.
_IDENT_RE = re.compile(
    r"`([^`\n]{1,120})`"                                   # backticked span
    r"|\b([A-Za-z_][A-Za-z0-9_]*\(\))"                     # name()
    r"|\b([A-Z][a-z0-9]+(?:[A-Z][A-Za-z0-9]*)+)\b"         # CamelCase
    r"|\b([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+)\b"      # dotted.path
    r"|\b([a-z][a-z0-9]*_[a-z0-9_]+)\b"                    # snake_case
)
_FILE_RE = re.compile(r"\b([\w./\\-]+\.[A-Za-z]{1,10})\b")


def _identifiers(sentence: str) -> list[str]:
    out: list[str] = []
    for m in _IDENT_RE.finditer(sentence):
        ident = next(g for g in m.groups() if g)
        ident = ident.strip()
        if ident and ident not in out:
            out.append(ident)
    return out


def extract_claims(text: str) -> list[Claim]:
    """Split text into sentences and mine conservative structural claims."""
    claims: list[Claim] = []
    seen: set[tuple[str, str, str]] = set()

    def add(subject: str, relation: str, obj: str, raw: str) -> None:
        key = (subject.lower(), relation, obj.lower())
        if key not in seen:
            seen.add(key)
            claims.append(Claim(subject=subject, relation=relation, object=obj, raw=raw.strip()))

    for sentence in re.split(r"(?<=[.!?;\n])\s+", text):
        idents = _identifiers(sentence)
        if not idents:
            continue
        matched_relation = False
        # defined_in first: "`foo` is defined in bar.py"
        dm = _DEFINED_IN_RE.search(sentence)
        if dm and idents:
            fm = _FILE_RE.search(sentence, dm.end())
            if fm:
                add(idents[0], "defined_in", fm.group(1), sentence)
                matched_relation = True
        if len(idents) >= 2:
            for pattern, relation in _RELATION_PATTERNS:
                m = pattern.search(sentence)
                if not m:
                    continue
                # subject = last identifier before the verb, object = first after.
                before = [i for i in idents if sentence.find(i) < m.start()]
                after = [i for i in idents if sentence.find(i) >= m.end()]
                if before and after:
                    add(before[-1], relation, after[0], sentence)
                    matched_relation = True
                break
        if not matched_relation:
            for ident in idents:
                add(ident, "exists", "", sentence)
    return claims


def parse_claims_json(raw: str) -> list[Claim]:
    """Parse the structured claims interface: a JSON list of claim objects."""
    data = json.loads(raw)
    if isinstance(data, dict):
        data = data.get("claims", [])
    if not isinstance(data, list):
        raise ValueError("claims JSON must be a list or {'claims': [...]}")
    out: list[Claim] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict) or not item.get("subject") or not item.get("relation"):
            raise ValueError(f"claim #{i} must be an object with 'subject' and 'relation'")
        out.append(Claim(
            subject=str(item["subject"]),
            relation=str(item["relation"]),
            object=str(item.get("object") or ""),
            raw=str(item.get("raw") or ""),
        ))
    return out


def summarize(verdicts: list[Verdict]) -> dict:
    counts = {VERIFIED: 0, VERIFIED_INDIRECT: 0, UNKNOWN: 0, REFUTED: 0}
    for v in verdicts:
        counts[v.verdict] = counts.get(v.verdict, 0) + 1
    total = len(verdicts)
    return {
        "total": total,
        "verified": counts[VERIFIED],
        "verified_indirect": counts[VERIFIED_INDIRECT],
        "unknown": counts[UNKNOWN],
        "refuted": counts[REFUTED],
    }


_MARKS = {VERIFIED: "[ok]", VERIFIED_INDIRECT: "[~]", UNKNOWN: "[?]", REFUTED: "[XX]"}


def render_report(verdicts: list[Verdict]) -> str:
    """Human-readable verdict listing (ASCII-safe for Windows consoles)."""
    lines: list[str] = []
    for v in verdicts:
        head = f"{_MARKS[v.verdict]} {v.verdict}: {v.claim.subject}"
        if v.claim.relation != "exists":
            head += f" {v.claim.relation} {v.claim.object}".rstrip()
        lines.append(head)
        if v.evidence:
            conf = f" [{v.confidence}]" if v.confidence else ""
            lines.append(f"     {v.evidence}{conf}")
    s = summarize(verdicts)
    lines.append("")
    lines.append(
        f"{s['total']} claim(s): {s['verified']} verified, "
        f"{s['verified_indirect']} indirect, {s['unknown']} unknown, {s['refuted']} refuted"
    )
    return "\n".join(lines)


def run_verify(
    graph_path: str | Path,
    *,
    text: str | None = None,
    claims_json: str | None = None,
    max_hops: int = DEFAULT_MAX_HOPS,
) -> tuple[list[Verdict], dict]:
    """Library entry point: verify text or structured claims against a graph."""
    if (text is None) == (claims_json is None):
        raise ValueError("provide exactly one of text= or claims_json=")
    claims = parse_claims_json(claims_json) if claims_json is not None else extract_claims(text or "")
    G = load_graph(graph_path)
    verdicts = check_claims(G, claims, max_hops=max_hops)
    return verdicts, summarize(verdicts)
