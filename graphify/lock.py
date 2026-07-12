# The genetic lock: make hallucinated APIs impossible, not just detected.
#
# The knowledge graph knows every callable, class, and module that actually
# exists in the project — its DNA. This module compiles that DNA into:
#
#   1. a SYMBOL SPACE the checker judges generated code against: every
#      call/import in a draft must resolve to the graph, the draft itself,
#      Python's builtins/stdlib, or a declared dependency — anything else is
#      a violation with nearest-real-symbol suggestions attached;
#   2. a REPAIR LOOP (`locked_generate`) for any LLM backend: draft → check →
#      violations fed back with suggestions → redraft, until clean or the
#      round budget ends. The model cannot ship a call that doesn't resolve;
#   3. HARD-LOCK artifacts for local runtimes: a JSON schema whose enum lists
#      only real symbols (Ollama structured outputs) and a GBNF plan grammar
#      (llama.cpp) — decoding-level masks under which a model physically
#      cannot NAME a nonexistent symbol while planning its API calls.
#
# Precision over recall throughout: a false "symbol doesn't exist" would make
# the lock unwearable, so anything ambiguous is allowed, never flagged.
from __future__ import annotations

import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

# Symbol-count ceiling for hard-lock artifacts: enum/grammar size must stay
# inference-friendly. Highest-degree symbols win (they are the real API).
MAX_HARD_SYMBOLS = 2000

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass
class SymbolSpace:
    """Everything a draft is allowed to reference, compiled from the graph."""

    callables: set[str] = field(default_factory=set)   # foo (from "foo()" labels)
    classes: set[str] = field(default_factory=set)     # Foo
    modules: set[str] = field(default_factory=set)     # importable module stems
    members: dict[str, set[str]] = field(default_factory=dict)  # module -> member names
    deps: set[str] = field(default_factory=set)        # declared external deps
    degree: dict[str, int] = field(default_factory=dict)  # symbol -> graph degree

    @property
    def known_names(self) -> set[str]:
        return self.callables | self.classes | self.modules | self.deps

    def ranked_symbols(self, cap: int = MAX_HARD_SYMBOLS) -> list[str]:
        """Callables + classes, highest graph degree first (the real API surface)."""
        pool = sorted(
            self.callables | self.classes,
            key=lambda s: (-self.degree.get(s, 0), s),
        )
        return pool[:cap]


def _label_symbol(label: str) -> str | None:
    """'validate_token()' -> 'validate_token'; '.method()' -> 'method';
    non-identifier labels (sentences, files with dots) -> None."""
    label = label.strip()
    if label.endswith("()"):
        label = label[:-2]
    label = label.lstrip(".")
    return label if _IDENT_RE.match(label) else None


def build_symbol_space(G: nx.Graph, repo_root: Path | None = None) -> SymbolSpace:
    """Compile the project's DNA out of the graph (plus declared deps)."""
    space = SymbolSpace()
    for nid, data in G.nodes(data=True):
        label = str(data.get("label") or "")
        ftype = str(data.get("file_type") or "")
        deg = G.degree(nid)
        # Package roots are directories, not .py labels — without them a
        # legitimate `from mypkg.mod import x` gets falsely flagged. Every
        # identifier-shaped path segment is importable enough to allow.
        src = str(data.get("source_file") or "").replace("\\", "/")
        for seg in src.split("/")[:-1]:
            if _IDENT_RE.match(seg):
                space.modules.add(seg)
        if label.endswith(".py"):
            space.modules.add(label[:-3])
            continue
        sym = _label_symbol(label)
        if not sym:
            continue
        if ftype and ftype != "code":
            continue  # doc/image concept nodes are not callable API
        if label.endswith("()"):
            space.callables.add(sym)
        elif sym[0].isupper():
            space.classes.add(sym)
        else:
            # bare lowercase identifier node (constant, module stem, resource)
            space.modules.add(sym)
        space.degree[sym] = max(space.degree.get(sym, 0), deg)

    # module -> members (contains/method edges), for attribute-call checking
    directed = hasattr(G, "out_edges")
    if directed:
        for u, v, d in G.edges(data=True):
            if str(d.get("relation") or "") not in ("contains", "method"):
                continue
            mod = str(G.nodes[u].get("label") or "")
            mod = mod[:-3] if mod.endswith(".py") else mod
            member = _label_symbol(str(G.nodes[v].get("label") or ""))
            if mod and member and _IDENT_RE.match(mod):
                space.members.setdefault(mod, set()).add(member)

    if repo_root is not None:
        space.deps |= _declared_deps(Path(repo_root))
    return space


def _declared_deps(repo_root: Path) -> set[str]:
    """Top-level import names a project may legitimately use: declared
    dependencies from pyproject/requirements (normalized to import-ish form)."""
    deps: set[str] = set()
    try:
        from graphify.manifest_ingest import _pep508_name
    except ImportError:  # pragma: no cover - manifest module always ships
        _pep508_name = lambda s: re.split(r"[\s<>=!~;\[\(]", s.strip(), maxsplit=1)[0]  # noqa: E731

    pp = repo_root / "pyproject.toml"
    if pp.exists():
        try:
            import tomllib
            data = tomllib.loads(pp.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            data = {}
        project = data.get("project", {}) if isinstance(data, dict) else {}
        raw: list[str] = list(project.get("dependencies") or [])
        for extra in (project.get("optional-dependencies") or {}).values():
            raw.extend(extra or [])
        for spec in raw:
            name = _pep508_name(str(spec))
            if name:
                deps.add(name.lower().replace("-", "_"))
    req = repo_root / "requirements.txt"
    if req.exists():
        for line in req.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "-")):
                name = _pep508_name(line)
                if name:
                    deps.add(name.lower().replace("-", "_"))
    return deps


# ── draft checking ────────────────────────────────────────────────────────────

@dataclass
class Violation:
    kind: str          # "call" | "import" | "member"
    name: str
    line: int
    suggestions: list[str] = field(default_factory=list)

    def render(self) -> str:
        s = f"line {self.line}: {self.kind} '{self.name}' does not exist in this project"
        if self.suggestions:
            s += f" — did you mean: {', '.join(self.suggestions)}?"
        return s


def _stdlib_modules() -> set[str]:
    mods = set(getattr(sys, "stdlib_module_names", ()))
    mods |= {"typing_extensions"}  # ubiquitous quasi-stdlib
    return mods


def _suggest(space: SymbolSpace, name: str, k: int = 3, *, pool: set[str] | None = None) -> list[str]:
    """Nearest real symbols. The pool must match the violation kind: an import
    suggestion drawn from function names once told a model 'did you mean X'
    for the very X it had just been refused — feedback must be actionable."""
    try:
        from rapidfuzz import process as _rf_process
    except ImportError:  # pragma: no cover - rapidfuzz is a core dep
        return []
    candidates = list(pool if pool is not None else space.known_names)
    if not candidates:
        return []
    hits = _rf_process.extract(name, candidates, limit=k, score_cutoff=70)
    return [h[0] for h in hits if h[0] != name]


class _DraftIndex(ast.NodeVisitor):
    """Names a draft defines for itself (defs, classes, assigns, params,
    imports with their aliases, comprehension targets) — all exempt."""

    def __init__(self) -> None:
        self.defined: set[str] = set()
        self.imported_modules: dict[str, str] = {}  # alias -> module root
        self.calls: list[tuple[str, int]] = []
        self.member_calls: list[tuple[str, str, int]] = []  # (receiver, attr, line)
        self.imports: list[tuple[str, int]] = []
        self.from_imports: list[tuple[str, str, str, int]] = []  # (root, full_module, name, line)

    # definitions
    def visit_FunctionDef(self, node):  # noqa: N802
        self.defined.add(node.name)
        for a in list(node.args.args) + list(node.args.kwonlyargs) + list(getattr(node.args, "posonlyargs", [])):
            self.defined.add(a.arg)
        if node.args.vararg:
            self.defined.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.defined.add(node.args.kwarg.arg)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # noqa: N815

    def visit_ClassDef(self, node):  # noqa: N802
        self.defined.add(node.name)
        self.generic_visit(node)

    def visit_Name(self, node):  # noqa: N802
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.defined.add(node.id)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):  # noqa: N802
        if node.name:
            self.defined.add(node.name)
        self.generic_visit(node)

    # imports
    def visit_Import(self, node):  # noqa: N802
        for alias in node.names:
            root = alias.name.split(".")[0]
            self.imports.append((root, node.lineno))
            self.imported_modules[alias.asname or root] = root
            self.defined.add(alias.asname or root)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):  # noqa: N802
        if node.level == 0 and node.module:
            root = node.module.split(".")[0]
            self.imports.append((root, node.lineno))
            for alias in node.names:
                self.defined.add(alias.asname or alias.name)
                # Remember what was pulled from where: a hallucinated name in
                # `from project_mod import ghost` must not hide behind the
                # alias exemption (checked only for project modules).
                self.from_imports.append((root, node.module, alias.name, node.lineno))
        self.generic_visit(node)

    # calls
    def visit_Call(self, node):  # noqa: N802
        f = node.func
        if isinstance(f, ast.Name):
            self.calls.append((f.id, node.lineno))
        elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            self.member_calls.append((f.value.id, f.attr, node.lineno))
        self.generic_visit(node)


def check_python(code: str, space: SymbolSpace) -> list[Violation]:
    """Judge a Python draft against the symbol space.

    Flags only what is PROVABLY foreign: a bare-name call that resolves
    nowhere, an import of a module that is neither project, stdlib, nor a
    declared dependency, and a member call on a project module whose member
    list is known and lacks the attribute. Everything ambiguous passes.
    A draft that does not parse yields a single syntax violation.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [Violation("syntax", str(e.msg or "invalid syntax"), int(e.lineno or 0))]

    idx = _DraftIndex()
    idx.visit(tree)
    import builtins as _b
    builtins_names = set(dir(_b))
    stdlib = _stdlib_modules()

    out: list[Violation] = []

    import_pool = space.modules | space.deps
    for root, line in idx.imports:
        norm = root.lower()
        if (root in space.modules or norm in space.modules or root in stdlib
                or norm in space.deps or root in space.deps):
            continue
        out.append(Violation("import", root, line, _suggest(space, root, pool=import_pool)))

    # `from project_pkg.sub import name`: for project-rooted imports, every
    # dotted segment must be a real module AND the leaf name must exist —
    # otherwise a model can weld two real fragments into a fabricated path
    # ("from prs.sanitization import _node_label") and slip through. Stdlib
    # and dependency modules stay unjudged (their internals are unknown).
    for root, full_module, name, line in idx.from_imports:
        if root in stdlib or root.lower() in space.deps or root in space.deps:
            continue
        if root not in space.modules and root.lower() not in space.modules:
            continue  # unknown root already flagged above
        segments = full_module.split(".")
        ghost_seg = next((s for s in segments[1:] if s not in space.modules), None)
        if ghost_seg is not None:
            out.append(Violation("import", full_module, line,
                                 _suggest(space, ghost_seg, pool=space.modules)))
            continue
        if name == "*":
            continue
        leaf = segments[-1]
        known_members = space.members.get(leaf)
        if known_members is not None:
            # The leaf module's member list is known: the name must be in it.
            if name in known_members or name in space.modules:
                continue
            out.append(Violation("import", f"{full_module}...{name}", line,
                                 _suggest(space, name, pool=known_members | space.modules)))
        elif name not in space.known_names:
            member_pool = space.callables | space.classes
            out.append(Violation("import", f"{full_module}...{name}", line,
                                 _suggest(space, name, pool=member_pool)))

    for name, line in idx.calls:
        if (name in idx.defined or name in builtins_names
                or name in space.callables or name in space.classes
                or name in idx.imported_modules):
            continue
        out.append(Violation("call", name, line, _suggest(space, name)))

    for receiver, attr, line in idx.member_calls:
        mod = idx.imported_modules.get(receiver)
        # Only judge receivers that are imports of PROJECT modules with a
        # known member list; objects/vars/stdlib receivers stay unjudged.
        if not mod or mod not in space.members:
            continue
        if attr in space.members[mod] or attr in idx.defined:
            continue
        pool = space.members[mod]
        sugg: list[str] = []
        try:
            from rapidfuzz import process as _rf_process
            sugg = [h[0] for h in _rf_process.extract(attr, list(pool), limit=3, score_cutoff=70)]
        except ImportError:  # pragma: no cover
            pass
        out.append(Violation("member", f"{receiver}.{attr}", line, sugg))

    return out


# ── hard-lock artifacts ───────────────────────────────────────────────────────

def emit_enum_schema(space: SymbolSpace, *, cap: int = MAX_HARD_SYMBOLS) -> dict:
    """JSON schema for an API-call plan whose symbols are enum-locked to the
    graph. Backends with structured outputs (Ollama, OpenAI-compat) enforce
    the enum at decode time: the model cannot NAME a symbol that isn't real."""
    symbols = space.ranked_symbols(cap)
    return {
        "type": "object",
        "properties": {
            "plan": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "symbol": {"type": "string", "enum": symbols},
                        "purpose": {"type": "string", "maxLength": 120},
                    },
                    "required": ["symbol", "purpose"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["plan"],
        "additionalProperties": False,
    }


def _gbnf_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def emit_gbnf(space: SymbolSpace, *, cap: int = MAX_HARD_SYMBOLS) -> str:
    """GBNF plan grammar for llama.cpp-family runtimes: each plan line must
    name a real symbol — the sampler masks every other continuation."""
    symbols = space.ranked_symbols(cap)
    if not symbols:
        symbols = ["__no_symbols_in_graph__"]
    alts = " | ".join(f'"{_gbnf_escape(s)}"' for s in symbols)
    return (
        "# Sanad genetic-lock plan grammar (auto-generated from graph.json)\n"
        "root ::= line+\n"
        'line ::= "CALL " symbol " # " purpose "\\n"\n'
        f"symbol ::= {alts}\n"
        "purpose ::= [^\\n]+\n"
    )


# ── locked generation (repair loop, any backend) ─────────────────────────────

_GEN_SYSTEM = """You write Python code for an existing project. HARD RULES:
- Only call functions/classes that exist in the project, Python builtins,
  the stdlib, or the project's declared dependencies.
- Prefer the project's own APIs. Do not invent helpers that don't exist.
- Reply with ONLY a Python code block, no prose."""


def _extract_code(reply: str) -> str:
    m = re.search(r"```(?:python)?\s*\n(.*?)```", reply, re.DOTALL)
    return (m.group(1) if m else reply).strip()


def api_hints_for_task(G: nx.Graph, task: str, *, k: int = 12) -> list[str]:
    """Graph-grounded menu for a generation task: the top real code symbols
    matching the task's words, with their files. Fed into the first prompt so
    a small model starts from the actual API instead of guessing names."""
    from graphify.serve import _score_nodes

    hints: list[str] = []
    for _score, nid in _score_nodes(G, [t.lower() for t in task.split()]):
        data = G.nodes[nid]
        if str(data.get("file_type") or "") != "code":
            continue
        label = str(data.get("label") or nid)
        src = str(data.get("source_file") or "")
        hints.append(f"{label} ({src})" if src else label)
        if len(hints) >= k:
            break
    return hints


def locked_generate(
    task: str,
    space: SymbolSpace,
    *,
    backend: str,
    model: str | None = None,
    rounds: int = 3,
    max_tokens: int = 1200,
    usage_out: dict | None = None,
    on_round=None,
    api_hints: list[str] | None = None,
) -> tuple[str, list[Violation], int]:
    """Generate code that survives the lock: draft, check, feed violations
    (with nearest-real-symbol suggestions) back, repeat.

    Returns (code, remaining_violations, rounds_used). Violation-free exit is
    the goal; anything left after the budget is returned for the caller to
    reject or surface — the lock never silently passes dirty code.
    """
    from graphify.llm import _call_llm

    menu = ""
    if api_hints:
        menu = "\n\nRelevant existing APIs in this project:\n" + "\n".join(
            f"- {h}" for h in api_hints
        )
    prompt = f"{_GEN_SYSTEM}\n\nTask: {task}{menu}"
    code = ""
    violations: list[Violation] = []
    used = 0
    for r in range(1, rounds + 1):
        used = r
        reply = _call_llm(prompt, backend=backend, model=model,
                          max_tokens=max_tokens, usage_out=usage_out)
        code = _extract_code(reply)
        violations = check_python(code, space)
        if on_round is not None:
            on_round(r, code, violations)
        if not violations:
            return code, [], used
        issues = "\n".join(f"- {v.render()}" for v in violations)
        prompt = (
            f"{_GEN_SYSTEM}\n\nTask: {task}{menu}\n\n"
            f"Your previous draft:\n```python\n{code}\n```\n\n"
            f"It references symbols that DO NOT EXIST in this project:\n{issues}\n\n"
            f"Rewrite the code using only real symbols. Reply with only the code block."
        )
    return code, violations, used


def render_check_report(violations: list[Violation]) -> str:
    if not violations:
        return "[ok] LOCKED_PASS: every call and import resolves to a real symbol"
    lines = [f"[XX] LOCK VIOLATIONS ({len(violations)}):"]
    for v in violations:
        lines.append(f"  {v.render()}")
    return "\n".join(lines)
