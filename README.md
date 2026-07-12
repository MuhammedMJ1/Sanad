<div align="center">

# Sanad — سند

**A graph brain for AI coding agents.**
*No answer without a chain of proof.*

[العربية](README.ar.md)

</div>

---

In hadith scholarship, no statement is accepted without a **sanad** — a verified chain of transmission back to the source. Sanad applies the same standard to AI and code: **no claim about your codebase passes unless the knowledge graph can prove it.**

Sanad maps any project into a deterministic knowledge graph (tree-sitter AST — no LLM, zero cost, nothing leaves your machine), then gives AI coding agents four abilities that don't exist together anywhere else:

| Pillar | Command | What it does |
|---|---|---|
| 🛡️ **Hallucination Gate** | `sanad verify` | Every structural claim an AI makes ("X calls Y", "Z is defined in F") is mechanically judged against the graph: **VERIFIED** (with proof path), **VERIFIED_INDIRECT**, **UNKNOWN**, or **REFUTED**. `--strict` blocks refuted answers with a non-zero exit code. |
| 🔮 **Blast-Radius Oracle** | `sanad predict` / `check-impact` | Before an edit: predicts every file the change should ripple into and saves it as a contract. After the edit: diffs reality against the contract. A change outside the prediction — the classic "I edited something I didn't understand" — is flagged as a **DEVIATION**. |
| 🧠 **Graph-Ops Thinking** | `sanad ops` / `think` | Instead of pasting files into a model, the model emits tiny ops (`find`, `callers`, `path`, `expand`...) and the graph engine computes locally for free. Nodes get short refs (`n1`, `n2`) so follow-ups cost a few tokens. Small models investigate like detectives — deep multi-hop reasoning at near-constant token cost, and they *cannot* invent a function that doesn't exist. |
| ⚖️ **Lens Council** | `sanad council` | The same small model is convened as several voices — usage lens, dependency lens, architecture lens, evidence lens — each running its own scoped investigation. A reconciliation step merges them, then the Gate judges the consensus and **forces a revision** of any refuted claim. |
| 🩹 **Scar Tissue** | `sanad scars` | Mines your git history (local, no LLM) into per-file **danger scores** (how often edits here needed a fix/revert) and **co-change couples**. `predict`/`check-impact` then warn: *"you're touching A without B, but 87% of past A-edits also touched B"*. Experience no frontier model has cold. |
| 🧬 **Genetic Lock** | `sanad lock-check` / `lock-gen` / `lock-grammar` | The graph compiles into the project's symbol space. Generated code that references a nonexistent API is rejected with the nearest real symbol suggested (`lock-check`, repair-loop `lock-gen`) — or made **unspeakable at decode time** via enum-schema / GBNF artifacts for local models (`lock-grammar`). |
| 🌪️ **Wind Tunnel** | `sanad tunnel` | Slices the minimal import closure for a change out of the graph, copies it into a scratch sandbox, then **really imports it and really runs** the graph-selected tests — optionally with a model's draft laid over a file — before the change ever lands. Reality instead of imagination, for zero tokens. |
| 🧪 **Sterile Memory** | `sanad memory` / `think --remember` | Permanent knowledge that cannot rot: an insight is admitted **only** if the Gate proves every claim in it; `reverify` re-judges the whole store as the code evolves, quarantining what stopped being true (and resurrecting it after a revert). Every verified investigation makes the system permanently smarter. |

## Measured, not promised

All numbers below are from real runs on this repository's own graph (10,900+ nodes):

- **Gate evaluation**: 10 true claims + 10 planted hallucinations (wrong files, invented functions, reversed call directions) → **10/10 true claims passed, 10/10 hallucinations caught**. During development the gate also refuted a claim sourced from the project's *own stale documentation* — a real hallucination, caught mechanically.
- **Think loop**: `gemini-3.1-flash-lite` (the cheapest tier) answered a real architecture question in 9 ops, **11.8k input / 213 output tokens (~$0.0066)** — answer fully correct and gate-verified 10/10.
- **Council**: three voices, 15 ops, consensus on a blast-radius question — **13/13 claims verified, ~$0.0088** total.
- **Genetic Lock**: planted hallucinations (`sanitize_labell`, fabricated import paths) caught with the correct suggestion first; with the graph-grounded API menu, the first draft came out **violation-free at ~$0.0004**.
- **Wind Tunnel**: a logic-sabotaged draft (correct syntax, wrong behavior) was exposed by really running the graph-selected tests in a sliced sandbox — in seconds, for **zero tokens**.
- **Scar Tissue**: mined 1,000+ commits in seconds; flagged a module where **67% of its 30 past edits** needed a follow-up fix.

## Quickstart

```bash
# 1. Build the graph (local, free, no API key needed)
sanad update .

# 2. Gate an AI's answer about your code
sanad verify "The \`login()\` function calls \`validate_token()\`." --strict

# 3. Hold an edit accountable
sanad predict "src/auth.py"        # before editing
# ... edit, then: sanad update .
sanad check-impact --strict        # DEVIATION = it touched what it didn't predict

# 4. Let a small model think with the graph
sanad think "Which module is the security chokepoint?" --verify

# 5. Convene the council
sanad council "What breaks if we change sanitize_label's signature?"

# 6. Or drive the ops yourself / from any agent (no API key)
sanad ops --new "find auth"
sanad ops "callers n1"

# 7. Inject 20 years of instinct from your git history (local, free)
sanad scars .
sanad scars --file src/auth.py

# 8. Generate code that cannot reference a nonexistent API
sanad lock-gen "add a helper that sanitizes labels using the project's sanitizer"
sanad lock-check draft.py            # judge any code against the symbol space

# 9. Test a draft against reality before it lands
sanad tunnel "src/auth.py" --draft new_auth.py --at src/auth.py

# 10. Grow a memory that cannot rot
sanad memory add "\`login()\` calls \`validate_token()\`."   # only enters if proven
sanad memory reverify                                       # re-judge after code changes
sanad think "..." --remember                                # auto-store verified answers
```

Works with **Claude Code, Gemini, Cursor, Codex, Copilot and 15+ agents** — `sanad install` registers the skill. Graph reasoning backends: Gemini, Claude, OpenAI, DeepSeek, Kimi, Ollama (local), Bedrock, Azure.

## Why not just RAG?

Vector search retrieves *similar text*; it cannot tell you that a claim is **false**. Sanad's graph is built deterministically from the AST, so it is ground truth for structure: who calls whom, what imports what, where things are defined. That's what makes refutation — not just retrieval — possible, and refutation is what kills hallucinations.

```
question ──▶ small model ──▶ op (a few tokens)
                 ▲               │
                 │               ▼
        compact result ◀── graph engine (local, free, cannot lie)
                 │
                 ▼
        answer ──▶ Hallucination Gate ──▶ proof-carrying reply
```

## Credits & license

Sanad is built on **[graphify](https://github.com/Graphify-Labs/graphify)** by Graphify Labs (MIT) — the deterministic extraction pipeline, graph builder, and query tools come from that excellent foundation (the upstream README is preserved at `docs/graphify-upstream-README.md`). The Sanad layer — hallucination gate (`factcheck.py`), blast-radius oracle (`impact.py`), graph-ops thinking engine (`graphmind.py`), and lens council (`council.py`) — plus full Windows support, ships under the same MIT license.

**لا إجابة بلا سند — No answer without a chain of proof.**
