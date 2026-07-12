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

## Measured, not promised

All numbers below are from real runs on this repository's own graph (10,900+ nodes):

- **Gate evaluation**: 10 true claims + 10 planted hallucinations (wrong files, invented functions, reversed call directions) → **10/10 true claims passed, 10/10 hallucinations caught**. During development the gate also refuted a claim sourced from the project's *own stale documentation* — a real hallucination, caught mechanically.
- **Think loop**: `gemini-3.1-flash-lite` (the cheapest tier) answered a real architecture question in 9 ops, **11.8k input / 213 output tokens (~$0.0066)** — answer fully correct and gate-verified 10/10.
- **Council**: three voices, 15 ops, consensus on a blast-radius question — **13/13 claims verified, ~$0.0088** total.

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
