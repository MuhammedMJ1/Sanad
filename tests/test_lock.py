"""Tests for lock.py - the genetic lock.

A small graph provides the project DNA: validate_token()/login() callables,
a Session class, an auth module with known members. The checker must catch
provably-foreign calls/imports/members with useful suggestions, tolerate
everything legitimate (locals, builtins, stdlib, declared deps), the hard-lock
artifacts must enum only real symbols, and the repair loop must converge.
"""
import json

import networkx as nx
import pytest

from graphify.lock import (
    MAX_HARD_SYMBOLS,
    SymbolSpace,
    build_symbol_space,
    check_python,
    emit_enum_schema,
    emit_gbnf,
    locked_generate,
    render_check_report,
)


def _graph() -> nx.DiGraph:
    G = nx.DiGraph()
    G.add_node("auth_py", label="auth.py", source_file="src/auth.py", file_type="code")
    G.add_node("login", label="login()", source_file="src/auth.py", file_type="code")
    G.add_node("validate", label="validate_token()", source_file="src/auth.py", file_type="code")
    G.add_node("session_cls", label="Session", source_file="src/session.py", file_type="code")
    G.add_node("doc_node", label="deployment guide", file_type="document")
    G.add_edge("auth_py", "login", relation="contains")
    G.add_edge("auth_py", "validate", relation="contains")
    # degree shaping: validate_token is the hub (degree 3 vs login's 2)
    G.add_edge("login", "validate", relation="calls")
    G.add_edge("session_cls", "validate", relation="uses")
    return G


@pytest.fixture()
def space() -> SymbolSpace:
    return build_symbol_space(_graph())


# ── symbol space compilation ─────────────────────────────────────────────────

def test_space_collects_callables_classes_modules(space):
    assert "login" in space.callables
    assert "validate_token" in space.callables
    assert "Session" in space.classes
    assert "auth" in space.modules


def test_space_module_members(space):
    assert space.members["auth"] == {"login", "validate_token"}


def test_space_excludes_non_code_and_non_identifier_labels(space):
    assert "deployment guide" not in space.known_names
    assert "deployment" not in space.known_names


def test_ranked_symbols_orders_by_degree(space):
    ranked = space.ranked_symbols()
    assert ranked[0] == "validate_token"  # highest degree hub first
    assert set(ranked) == {"login", "validate_token", "Session"}


def test_dep_specs_fallback_regex_matches_tomllib_path():
    """The 3.10 fallback (no tomllib) must extract the same dep names."""
    from graphify.lock import _dep_specs_fallback
    text = (
        '[project]\nname="x"\nversion="0"\n'
        'dependencies=[\n  "requests>=2",\n  "python-dotenv",\n]\n'
        '[project.optional-dependencies]\n'
        'pdf=["pypdf>=6"]\nvideo=["yt-dlp"]\n'
        '[tool.other]\nignored=["not-a-dep"]\n'
    )
    specs = _dep_specs_fallback(text)
    assert "requests>=2" in specs and "python-dotenv" in specs
    assert "pypdf>=6" in specs and "yt-dlp" in specs
    assert "not-a-dep" not in specs


def test_declared_deps_from_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\nversion="0"\ndependencies=["requests>=2", "python-dotenv"]\n',
        encoding="utf-8",
    )
    s = build_symbol_space(_graph(), tmp_path)
    assert "requests" in s.deps
    assert "python_dotenv" in s.deps


# ── checking: catches what is provably foreign ───────────────────────────────

def test_hallucinated_call_is_caught_with_suggestion(space):
    code = "def f(t):\n    return validate_tokenn(t)\n"
    v = check_python(code, space)
    assert len(v) == 1
    assert v[0].kind == "call" and v[0].name == "validate_tokenn"
    assert "validate_token" in v[0].suggestions


def test_hallucinated_import_is_caught(space):
    v = check_python("import totally_made_up_pkg\n", space)
    assert len(v) == 1 and v[0].kind == "import"


def test_wrong_member_on_project_module_is_caught(space):
    code = "import auth\nauth.loginn('u')\n"
    v = check_python(code, space)
    assert len(v) == 1 and v[0].kind == "member"
    assert v[0].name == "auth.loginn"
    assert "login" in v[0].suggestions


def test_from_import_of_ghost_name_is_caught(space):
    """`from auth import ghost` must not hide behind the alias exemption."""
    code = "from auth import validate_tokenn\nx = validate_tokenn('t')\n"
    v = check_python(code, space)
    kinds = {x.kind for x in v}
    assert "import" in kinds
    imp = next(x for x in v if x.kind == "import")
    assert imp.name == "auth...validate_tokenn"
    assert "validate_token" in imp.suggestions


def test_from_import_of_real_name_passes(space):
    code = "from auth import validate_token\nx = validate_token('t')\n"
    assert check_python(code, space) == []


def test_fabricated_submodule_path_is_caught(space):
    """Welding two real fragments into a fake path must not pass: `auth` is
    real and `login` is real, but `auth.ghostpkg` is not a module chain."""
    code = "from auth.ghostpkg import login\nx = login('u')\n"
    v = check_python(code, space)
    assert len(v) == 1 and v[0].kind == "import"
    assert v[0].name == "auth.ghostpkg"


def test_real_submodule_chain_passes():
    """Directory segments from source_file paths count as importable modules
    (pkg/auth.py -> `from pkg.auth import login` must pass)."""
    G = nx.DiGraph()
    G.add_node("auth_py", label="auth.py", source_file="pkg/auth.py", file_type="code")
    G.add_node("login", label="login()", source_file="pkg/auth.py", file_type="code")
    G.add_edge("auth_py", "login", relation="contains")
    s = build_symbol_space(G)
    code = "from pkg.auth import login\nx = login('u')\n"
    assert check_python(code, s) == []


def test_import_suggestions_never_echo_the_rejected_name(space):
    """The pool must match the kind: a callable name must not be suggested as
    an importable module (that once told a model 'did you mean X' for the X
    it had just been refused)."""
    space.callables.add("ghost_pkg")  # same name exists as a callable
    v = check_python("import ghost_pkg\n", space)
    assert len(v) == 1
    assert "ghost_pkg" not in v[0].suggestions


def test_syntax_error_is_one_violation(space):
    v = check_python("def broken(:\n", space)
    assert len(v) == 1 and v[0].kind == "syntax"


# ── checking: tolerates everything legitimate ────────────────────────────────

def test_clean_draft_passes(space):
    code = (
        "import json\n"
        "import auth\n"
        "def handler(payload):\n"
        "    data = json.loads(payload)\n"
        "    return auth.login(data)\n"
    )
    assert check_python(code, space) == []


def test_locals_params_and_builtins_are_exempt(space):
    code = (
        "def f(callback):\n"
        "    items = [1, 2]\n"
        "    total = sum(items)\n"
        "    callback(total)\n"
        "    helper = lambda x: x\n"
        "    return helper(len(items))\n"
    )
    assert check_python(code, space) == []


def test_self_defined_functions_are_exempt(space):
    code = "def a():\n    return b()\n\ndef b():\n    return 1\n"
    assert check_python(code, space) == []


def test_declared_dep_import_and_object_members_unjudged(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\nversion="0"\ndependencies=["requests"]\n', encoding="utf-8"
    )
    s = build_symbol_space(_graph(), tmp_path)
    code = (
        "import requests\n"
        "def f(url):\n"
        "    r = requests.get(url)\n"   # dep module member: unjudged
        "    return r.json()\n"          # object member: unjudged
    )
    assert check_python(code, s) == []


def test_import_alias_receiver_checked_against_real_module(space):
    code = "import auth as a\nresult = a.login('u')\n"
    assert check_python(code, space) == []


# ── hard-lock artifacts ───────────────────────────────────────────────────────

def test_enum_schema_locks_symbols_to_graph(space):
    schema = emit_enum_schema(space)
    enum = schema["properties"]["plan"]["items"]["properties"]["symbol"]["enum"]
    assert set(enum) == {"login", "validate_token", "Session"}
    json.dumps(schema)  # must be serializable for backends


def test_enum_schema_cap(space):
    schema = emit_enum_schema(space, cap=1)
    enum = schema["properties"]["plan"]["items"]["properties"]["symbol"]["enum"]
    assert enum == ["validate_token"]


def test_gbnf_grammar_contains_only_real_symbols(space):
    g = emit_gbnf(space)
    assert '"validate_token"' in g and '"login"' in g and '"Session"' in g
    assert "root ::=" in g and "symbol ::=" in g
    assert "made_up" not in g


def test_gbnf_survives_empty_space():
    g = emit_gbnf(SymbolSpace())
    assert "__no_symbols_in_graph__" in g


def test_hard_symbol_cap_constant_sane():
    assert 100 <= MAX_HARD_SYMBOLS <= 20000


# ── locked generation repair loop ────────────────────────────────────────────

def test_locked_generate_converges_after_feedback(space, monkeypatch):
    replies = iter([
        "```python\nresult = validate_tokenn('x')\n```",          # hallucinated
        "```python\nresult = validate_token('x')\n```",           # fixed
    ])
    prompts: list[str] = []

    def fake_call(prompt, *, backend, model=None, max_tokens=0, usage_out=None):
        prompts.append(prompt)
        return next(replies)

    monkeypatch.setattr("graphify.llm._call_llm", fake_call)
    code, violations, used = locked_generate(
        "check a token", space, backend="gemini", rounds=3
    )
    assert violations == [] and used == 2
    assert "validate_token('x')" in code
    # the repair prompt carried the violation AND the suggestion
    assert "does not exist" in prompts[1]
    assert "did you mean: validate_token" in prompts[1]


def test_locked_generate_menu_reaches_the_prompt(space, monkeypatch):
    """api_hints must appear in BOTH the first prompt and repair prompts —
    the menu is how a small model finds the real API instead of guessing."""
    prompts: list[str] = []
    replies = iter([
        "```python\nghostt()\n```",
        "```python\nx = validate_token('t')\n```",
    ])

    def fake_call(prompt, **kw):
        prompts.append(prompt)
        return next(replies)

    monkeypatch.setattr("graphify.llm._call_llm", fake_call)
    code, violations, _ = locked_generate(
        "check a token", space, backend="gemini", rounds=3,
        api_hints=["validate_token() (src/auth.py)"],
    )
    assert violations == []
    assert all("validate_token() (src/auth.py)" in p for p in prompts)


def test_api_hints_for_task_ranks_code_symbols():
    from graphify.lock import api_hints_for_task
    hints = api_hints_for_task(_graph(), "validate a session token")
    assert any("validate_token()" in h for h in hints)
    assert all("deployment guide" not in h for h in hints)  # non-code excluded


def test_locked_generate_returns_dirty_after_budget(space, monkeypatch):
    monkeypatch.setattr(
        "graphify.llm._call_llm",
        lambda prompt, **kw: "```python\nghost_call()\n```",
    )
    code, violations, used = locked_generate("x", space, backend="gemini", rounds=2)
    assert used == 2 and len(violations) == 1
    assert violations[0].name == "ghost_call"


def test_render_check_report_shapes(space):
    assert "LOCKED_PASS" in render_check_report([])
    v = check_python("qqq_nope()\n", space)
    rep = render_check_report(v)
    assert "LOCK VIOLATIONS" in rep and "qqq_nope" in rep
