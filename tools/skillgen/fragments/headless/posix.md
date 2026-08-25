**Headless build path — MANDATORY when a Gemini key is set:** For any build request (bare path, fresh extraction, `--update`, `--mode deep`) when `GEMINI_API_KEY` or `GOOGLE_API_KEY` is set: do NOT run Steps 2–5 turn-by-turn — that orchestration re-reads the whole session context on every step and burns millions of tokens. After Step 1 resolves the interpreter, run the entire pipeline as two commands:

```bash
export PYTHONIOENCODING=utf-8
"$(cat graphify-out/.graphify_python)" -m graphify extract INPUT_PATH --backend gemini 2>&1 | tail -15
"$(cat graphify-out/.graphify_python)" -m graphify cluster-only INPUT_PATH 2>&1 | tail -10
```

Run the `extract` command with a 10-minute timeout (run it in the background for very large corpora). `extract` is the full pipeline headless — detect → AST → Gemini semantic extraction → merge → build → cluster → `graph.json` + `.graphify_analysis.json` (it also handles incremental `--update` runs via the manifest). `cluster-only` is self-contained: it names communities and regenerates `GRAPH_REPORT.md`, `graph.json`, and `graph.html`. After both commands succeed, skip straight to the final user summary at the end of Step 9 (paste the God Nodes / Surprising Connections / Suggested Questions sections) — do not run Steps 2–8 manually. Fall back to the step-by-step flow only if `graphify extract` exits non-zero for a reason you cannot fix; never fall back silently — tell the user why.
