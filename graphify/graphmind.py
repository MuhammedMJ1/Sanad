# Graph-ops thinking engine: the model steers, the graph computes.
#
# Instead of pasting file contents into an LLM and letting it "reason" in
# prose (expensive, hallucination-prone), the model emits one tiny operation
# per step — `find`, `expand`, `callers`, `path`, ... — and this engine
# executes it deterministically against graph.json, returning a compact
# result. The reasoning state (visited nodes, notes) lives HERE, not in the
# model's context, so:
#   - a small model can run long multi-hop investigations on a tiny budget,
#   - every intermediate fact comes from the graph and cannot be invented,
#   - nodes get short refs (n1, n2, ...) so follow-up ops cost a few tokens.
#
# Two drivers share the engine:
#   `graphify ops`   — any agent (or human) issues ops directly; session
#                      state persists across CLI invocations. No API key.
#   `graphify think` — an autonomous loop where the configured LLM backend
#                      emits ops until it answers; the answer can be piped
#                      through the factcheck hallucination gate (--verify).
from __future__ import annotations

import json
import shlex
from pathlib import Path

import networkx as nx

from graphify.affected import resolve_seed
from graphify.build import edge_data
from graphify.serve import _score_nodes

SESSION_FILENAME = ".graphify_mind_session.json"

# Caps keep every result small enough that a whole investigation fits in a
# few hundred tokens of transcript.
MAX_LIST = 12
MAX_FIND = 8
MAX_NOTE_CHARS = 500
MAX_OPS_HISTORY = 200

OPS_HELP = """ops language (one op per line):
  find <query>              locate nodes by name/keywords -> refs n1, n2, ...
  expand <ref> [in|out]     neighbors of a node (in = who points at it)
  callers <ref>             who calls this
  callees <ref>             what this calls
  members <ref>             what a file/class contains
  path <ref> -> <ref>       shortest connection between two nodes
  common <ref> -> <ref>     shared neighbors of two nodes
  source <ref>              file and line of a node
  community <ref>           the subsystem a node belongs to (top members)
  scars <ref>               git-history scars of a node's file (danger, co-change partners)
  note <text>               save a working-memory note
  notes                     list saved notes
  answer <text>             finish with the final answer
Refs: use n<K> from earlier results, or a quoted label like "login()"."""

_CALL_RELATIONS = ("calls", "indirect_call")
_MEMBER_RELATIONS = ("contains", "method")


class OpError(ValueError):
    """Raised for a malformed or unresolvable op; the message is model-facing."""


class MindSession:
    """Execution state for one investigation over one graph."""

    def __init__(self, G: nx.Graph, scars: dict | None = None):
        self.G = G
        self.scars = scars                  # optional git-history sidecar (scars.py)
        self.ref_ids: list[str] = []        # index -> node_id (ref nK = ref_ids[K-1])
        self._ref_of: dict[str, int] = {}   # node_id -> index
        self.notes: list[str] = []
        self.history: list[str] = []
        self.answer: str | None = None

    # ── refs ──────────────────────────────────────────────────────────────────

    def _ref(self, node_id: str) -> str:
        node_id = str(node_id)
        idx = self._ref_of.get(node_id)
        if idx is None:
            self.ref_ids.append(node_id)
            idx = len(self.ref_ids)
            self._ref_of[node_id] = idx
        return f"n{idx}"

    def _fmt(self, node_id: str, *, extra: str = "") -> str:
        data = self.G.nodes[node_id]
        label = str(data.get("label") or node_id)
        src = str(data.get("source_file") or "")
        loc = f" ({src})" if src else ""
        return f"{self._ref(node_id)}:{label}{loc}{extra}"

    def _resolve(self, token: str) -> str:
        """Resolve an op argument to a node id: nK ref, exact node, or search."""
        token = token.strip().strip('"').strip("'")
        if not token:
            raise OpError("empty node reference")
        if token.startswith("n") and token[1:].isdigit():
            idx = int(token[1:])
            if 1 <= idx <= len(self.ref_ids):
                return self.ref_ids[idx - 1]
            raise OpError(f"unknown ref {token} (have n1..n{len(self.ref_ids)})")
        seed = resolve_seed(self.G, token)
        if seed is not None:
            return seed
        scored = _score_nodes(self.G, [t.lower() for t in token.split()])
        if scored:
            return scored[0][1]
        raise OpError(f"no node matching {token!r} — try `find {token}` first")

    # ── op implementations ────────────────────────────────────────────────────

    def _op_find(self, arg: str) -> str:
        if not arg:
            raise OpError("usage: find <query>")
        scored = _score_nodes(self.G, [t.lower() for t in arg.split()])
        if not scored:
            return f"no matches for {arg!r}"
        lines = []
        for _score, nid in scored[:MAX_FIND]:
            deg = self.G.degree(nid)
            lines.append(self._fmt(nid, extra=f" [deg {deg}]"))
        if len(scored) > MAX_FIND:
            lines.append(f"... +{len(scored) - MAX_FIND} more")
        return "\n".join(lines)

    def _neighbors(self, nid: str, direction: str, relations: tuple[str, ...] | None) -> list[tuple[str, str, str]]:
        """(neighbor_id, relation, arrow) honoring direction and relation filter."""
        out: list[tuple[str, str, str]] = []
        directed = hasattr(self.G, "out_edges")
        if direction in ("out", "all") and directed:
            for _s, t, d in self.G.out_edges(nid, data=True):
                rel = str(d.get("relation") or "")
                if relations is None or rel in relations:
                    out.append((str(t), rel, "->"))
        if direction in ("in", "all") and directed:
            for s, _t, d in self.G.in_edges(nid, data=True):
                rel = str(d.get("relation") or "")
                if relations is None or rel in relations:
                    out.append((str(s), rel, "<-"))
        if not directed:
            for _s, t, d in self.G.edges(nid, data=True):
                rel = str(d.get("relation") or "")
                if relations is None or rel in relations:
                    out.append((str(t), rel, "--"))
        return out

    def _render_neighbors(self, nid: str, hits: list[tuple[str, str, str]], kind: str) -> str:
        if not hits:
            return f"{self._fmt(nid)}: no {kind}"
        # Highest-degree neighbors first: hubs are usually what the question is about.
        hits.sort(key=lambda h: -self.G.degree(h[0]))
        lines = [f"{self._fmt(nid)} {kind}:"]
        for other, rel, arrow in hits[:MAX_LIST]:
            lines.append(f"  {arrow} {self._fmt(other)} [{rel}]")
        if len(hits) > MAX_LIST:
            lines.append(f"  ... +{len(hits) - MAX_LIST} more")
        return "\n".join(lines)

    def _op_expand(self, arg: str) -> str:
        parts = arg.split()
        if not parts:
            raise OpError("usage: expand <ref> [in|out]")
        direction = "all"
        if parts[-1].lower() in ("in", "out", "all"):
            direction = parts[-1].lower()
            parts = parts[:-1]
        nid = self._resolve(" ".join(parts))
        return self._render_neighbors(nid, self._neighbors(nid, direction, None), f"neighbors ({direction})")

    def _op_callers(self, arg: str) -> str:
        nid = self._resolve(arg)
        return self._render_neighbors(nid, self._neighbors(nid, "in", _CALL_RELATIONS), "callers")

    def _op_callees(self, arg: str) -> str:
        nid = self._resolve(arg)
        return self._render_neighbors(nid, self._neighbors(nid, "out", _CALL_RELATIONS), "callees")

    def _op_members(self, arg: str) -> str:
        nid = self._resolve(arg)
        return self._render_neighbors(nid, self._neighbors(nid, "out", _MEMBER_RELATIONS), "members")

    def _split_pair(self, arg: str, op: str) -> tuple[str, str]:
        for sep in (" -> ", "->", " | "):
            if sep in arg:
                a, b = arg.split(sep, 1)
                if a.strip() and b.strip():
                    return a.strip(), b.strip()
        raise OpError(f"usage: {op} <ref> -> <ref>")

    def _op_path(self, arg: str) -> str:
        a_tok, b_tok = self._split_pair(arg, "path")
        a, b = self._resolve(a_tok), self._resolve(b_tok)
        if a == b:
            return "both sides resolve to the same node"
        try:
            nodes = nx.shortest_path(self.G.to_undirected(as_view=True), a, b)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return f"no path between {self._fmt(a)} and {self._fmt(b)}"
        segs = [self._fmt(nodes[0])]
        for u, v in zip(nodes, nodes[1:]):
            if self.G.has_edge(u, v):
                rel = str((edge_data(self.G, u, v) or {}).get("relation") or "?")
                segs.append(f"--{rel}--> {self._fmt(v)}")
            else:
                rel = str((edge_data(self.G, v, u) or {}).get("relation") or "?")
                segs.append(f"<--{rel}-- {self._fmt(v)}")
        return f"{len(nodes) - 1} hop(s): " + " ".join(segs)

    def _op_common(self, arg: str) -> str:
        a_tok, b_tok = self._split_pair(arg, "common")
        a, b = self._resolve(a_tok), self._resolve(b_tok)
        und = self.G.to_undirected(as_view=True)
        shared = sorted(set(und.neighbors(a)) & set(und.neighbors(b)),
                        key=lambda n: -self.G.degree(n))
        if not shared:
            return f"no shared neighbors between {self._fmt(a)} and {self._fmt(b)}"
        lines = [f"shared neighbors of {self._fmt(a)} and {self._fmt(b)}:"]
        for n in shared[:MAX_LIST]:
            lines.append(f"  {self._fmt(n)}")
        if len(shared) > MAX_LIST:
            lines.append(f"  ... +{len(shared) - MAX_LIST} more")
        return "\n".join(lines)

    def _op_source(self, arg: str) -> str:
        nid = self._resolve(arg)
        data = self.G.nodes[nid]
        src = str(data.get("source_file") or "unknown")
        loc = str(data.get("source_location") or "")
        conf = str(data.get("confidence") or "")
        tail = f" [{conf}]" if conf else ""
        return f"{self._fmt(nid)} at {src}{':' + loc if loc else ''}{tail}"

    def _op_community(self, arg: str) -> str:
        nid = self._resolve(arg)
        data = self.G.nodes[nid]
        cid = data.get("community")
        cname = data.get("community_name") or (f"community {cid}" if cid is not None else None)
        if cname is None:
            return f"{self._fmt(nid)}: no community data (graph built without clustering?)"
        members = [
            n for n, d in self.G.nodes(data=True) if d.get("community") == cid and n != nid
        ]
        members.sort(key=lambda n: -self.G.degree(n))
        lines = [f"{self._fmt(nid)} is in '{cname}' ({len(members) + 1} nodes); top members:"]
        for n in members[:MAX_LIST]:
            lines.append(f"  {self._fmt(n)}")
        return "\n".join(lines)

    def _op_scars(self, arg: str) -> str:
        nid = self._resolve(arg)
        if not self.scars:
            return "no scar data loaded — run `sanad scars` in the repo first"
        src = str(self.G.nodes[nid].get("source_file") or "")
        if not src:
            return f"{self._fmt(nid)}: node has no source file to look up"
        from graphify.scars import render_file_report
        return render_file_report(self.scars, src)

    def _op_note(self, arg: str) -> str:
        if not arg.strip():
            raise OpError("usage: note <text>")
        self.notes.append(arg.strip()[:MAX_NOTE_CHARS])
        return f"noted ({len(self.notes)} note(s))"

    def _op_notes(self, arg: str) -> str:
        if not self.notes:
            return "no notes yet"
        return "\n".join(f"{i + 1}. {n}" for i, n in enumerate(self.notes))

    # ── dispatch ──────────────────────────────────────────────────────────────

    _OPS = {
        "find": _op_find,
        "expand": _op_expand,
        "callers": _op_callers,
        "callees": _op_callees,
        "members": _op_members,
        "path": _op_path,
        "common": _op_common,
        "source": _op_source,
        "community": _op_community,
        "scars": _op_scars,
        "note": _op_note,
        "notes": _op_notes,
    }

    def execute(self, line: str) -> str:
        """Execute one op line; returns the compact result text.

        Malformed ops return an `error: ...` string instead of raising, so a
        driving model sees the mistake and can self-correct on the next step.
        """
        line = line.strip()
        if not line:
            return "error: empty op"
        op, _, arg = line.partition(" ")
        op = op.lower()
        if op == "help":
            return OPS_HELP
        if op == "answer":
            if not arg.strip():
                return "error: answer needs text"
            self.answer = arg.strip()
            result = "answer recorded"
        elif op in self._OPS:
            try:
                result = self._OPS[op](self, arg.strip())
            except OpError as e:
                result = f"error: {e}"
        else:
            result = f"error: unknown op {op!r} — say `help` for the op list"
        if len(self.history) < MAX_OPS_HISTORY:
            self.history.append(line)
        return result

    # ── persistence (drives `graphify ops` across CLI invocations) ───────────

    def to_state(self) -> dict:
        return {
            "version": 1,
            "ref_ids": self.ref_ids,
            "notes": self.notes,
            "history": self.history,
            "answer": self.answer,
        }

    @classmethod
    def from_state(cls, G: nx.Graph, state: dict, scars: dict | None = None) -> "MindSession":
        s = cls(G, scars)
        # Drop refs whose nodes vanished from a rebuilt graph; remaining refs
        # keep their ORIGINAL indices (a stale n7 must not silently become n5).
        for i, nid in enumerate(state.get("ref_ids", [])):
            nid = str(nid)
            if nid in G:
                s.ref_ids.append(nid)
                s._ref_of[nid] = i + 1
            else:
                s.ref_ids.append(nid)  # placeholder keeps numbering stable
        s.notes = [str(n) for n in state.get("notes", [])][:MAX_OPS_HISTORY]
        s.history = [str(h) for h in state.get("history", [])][:MAX_OPS_HISTORY]
        s.answer = state.get("answer")
        return s


def save_session(out_dir: Path, session: MindSession) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / SESSION_FILENAME
    p.write_text(json.dumps(session.to_state(), ensure_ascii=False), encoding="utf-8")
    return p


def load_session(out_dir: Path, G: nx.Graph, scars: dict | None = None) -> MindSession:
    p = out_dir / SESSION_FILENAME
    if not p.exists():
        return MindSession(G, scars)
    try:
        state = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return MindSession(G, scars)
    return MindSession.from_state(G, state, scars)


# ── autonomous think loop (`graphify think`) ─────────────────────────────────

THINK_SYSTEM = """You are investigating a codebase through its knowledge graph.
You cannot read files. You act ONLY by emitting exactly one op per turn.

{ops_help}

Rules:
- One op per reply. No prose, no markdown, no explanation — just the op line.
- Use refs (n1, n2...) from earlier results instead of retyping labels.
- Investigate until you can back the answer with graph evidence, then emit:
  answer <your conclusion, citing the refs/files you verified>
- If a result says `error:`, fix your op and try again.
- You have {budget} ops total. Be economical."""


def _parse_op_reply(reply: str) -> str:
    """Pull the first plausible op line out of a model reply."""
    for line in reply.strip().splitlines():
        line = line.strip().strip("`")
        if not line:
            continue
        head = line.split(" ", 1)[0].lower()
        if head in MindSession._OPS or head in ("answer", "help"):
            return line
    # Fall back to the first non-empty line so the error surfaces in-loop.
    for line in reply.strip().splitlines():
        if line.strip():
            return line.strip()
    return ""


def think(
    G: nx.Graph,
    question: str,
    *,
    backend: str,
    model: str | None = None,
    budget: int = 15,
    max_step_tokens: int = 300,
    usage_out: dict | None = None,
    on_step=None,
    perspective: str = "",
    scars: dict | None = None,
) -> tuple[str | None, list[tuple[str, str]]]:
    """Run the graph-ops reasoning loop until `answer` or op budget exhaustion.

    Returns (answer | None, trace) where trace is [(op, result), ...].
    ``on_step(op, result)`` is called after each executed op (CLI streaming).
    ``perspective`` (used by the council's lenses) is appended to the system
    prompt to constrain WHAT the voice investigates without changing HOW.
    The transcript sent to the model contains ONLY ops and compact results —
    never file contents — which is what keeps token cost near-constant.
    """
    from graphify.llm import _call_llm

    session = MindSession(G, scars)
    system = THINK_SYSTEM.format(ops_help=OPS_HELP, budget=budget)
    if perspective:
        system = f"{system}\n\nYour assigned perspective:\n{perspective}"
    trace: list[tuple[str, str]] = []

    for step in range(budget):
        transcript = "\n".join(
            f"> {op}\n{result}" for op, result in trace
        )
        remaining = budget - step
        prompt = (
            f"{system}\n\nQuestion: {question}\n\n"
            f"{transcript}\n\n({remaining} ops left) Next op:"
        )
        reply = _call_llm(
            prompt, backend=backend, model=model,
            max_tokens=max_step_tokens, usage_out=usage_out,
        )
        op_line = _parse_op_reply(reply)
        if not op_line:
            trace.append(("(empty reply)", "error: reply contained no op"))
            continue
        result = session.execute(op_line)
        trace.append((op_line, result))
        if on_step is not None:
            on_step(op_line, result)
        if session.answer is not None:
            return session.answer, trace
    return None, trace
