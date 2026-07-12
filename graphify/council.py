# Lens council: internal debate over graph evidence, not prose.
#
# The same (small) model is convened several times, each time as a "voice"
# locked to one investigative lens — who uses this? what does it depend on?
# how is it structured? what do the tests say? Each voice runs its own
# budgeted graph-ops loop (graphmind.think), so every fact a voice cites was
# computed by the graph engine, never imagined. A reconciliation step merges
# the voices into one consensus answer, and the factcheck hallucination gate
# then judges that answer mechanically: any refuted claim triggers a forced
# revision round with the gate's evidence injected. What survives is a
# multi-perspective answer in which every structural claim carries proof.
from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from graphify.factcheck import (
    REFUTED,
    check_claims,
    extract_claims,
    render_report,
    summarize,
)
from graphify.graphmind import think

# Investigative lenses. Each is a perspective preamble for graphmind.think —
# the op language and rules are shared; only the assignment differs.
LENSES: dict[str, str] = {
    "callers": (
        "You are the USAGE voice. Investigate who CALLS/USES/IMPORTS the "
        "things in the question — walk `callers`, `expand <ref> in`, and "
        "`path`. Your answer must describe the inbound dependency story."
    ),
    "callees": (
        "You are the DEPENDENCY voice. Investigate what the things in the "
        "question DEPEND ON — walk `callees`, `members`, `expand <ref> out`. "
        "Your answer must describe the outbound dependency story."
    ),
    "structure": (
        "You are the ARCHITECTURE voice. Investigate structure — which "
        "files/communities the things in the question live in (`community`, "
        "`members`, `common`, `source`). Your answer must describe where "
        "this sits in the system and what shares its neighborhood."
    ),
    "evidence": (
        "You are the EVIDENCE voice. Investigate tests and documentation — "
        "`find` test files and doc/rationale nodes near the things in the "
        "question and see what they connect to. Your answer must describe "
        "what the tests/docs actually exercise or record."
    ),
}

DEFAULT_LENSES = ("callers", "callees", "structure")
DEFAULT_LENS_BUDGET = 6
MAX_REVISIONS = 1

RECONCILE_PROMPT = """You are reconciling an internal debate about a codebase.
Question: {question}

Each voice below investigated the SAME question through a different lens of
the code knowledge graph. Their factual statements come from real graph
lookups.

{voices}

Write the single best final answer to the question:
- Merge the perspectives; keep only conclusions the voices' evidence supports.
- Name concrete functions/files (with their source files) — no vague prose.
- If voices disagree, say which reading the evidence favors and why.
- 5 sentences maximum.
Final answer:"""

REVISE_PROMPT = """Your previous answer contained claims the code knowledge
graph REFUTED. The graph is ground truth (built from the AST, not guesses).

Previous answer:
{answer}

Mechanical verification result:
{gate_report}

Rewrite the answer: drop or correct every refuted claim, keep verified ones,
and do not introduce new unverified specifics. 5 sentences maximum.
Revised answer:"""


@dataclass
class LensReport:
    name: str
    answer: str | None
    ops_used: int
    trace: list = field(default_factory=list)


@dataclass
class CouncilResult:
    question: str
    lens_reports: list[LensReport]
    final_answer: str
    gate_summary: dict
    gate_report: str
    revisions: int

    def to_dict(self) -> dict:
        return {
            "question": self.question,
            "lenses": [
                {"name": r.name, "answer": r.answer, "ops_used": r.ops_used}
                for r in self.lens_reports
            ],
            "final_answer": self.final_answer,
            "gate_summary": self.gate_summary,
            "revisions": self.revisions,
        }


def _gate(G: nx.Graph, answer: str) -> tuple[dict, str, int]:
    """Run the hallucination gate on an answer; returns (summary, report, refuted)."""
    claims = extract_claims(answer)
    if not claims:
        return ({"total": 0, "verified": 0, "verified_indirect": 0,
                 "unknown": 0, "refuted": 0}, "", 0)
    verdicts = check_claims(G, claims)
    s = summarize(verdicts)
    return s, render_report(verdicts), s.get("refuted", 0)


def convene(
    G: nx.Graph,
    question: str,
    *,
    backend: str,
    model: str | None = None,
    lenses: tuple[str, ...] = DEFAULT_LENSES,
    budget_per_lens: int = DEFAULT_LENS_BUDGET,
    verify: bool = True,
    max_revisions: int = MAX_REVISIONS,
    usage_out: dict | None = None,
    on_step=None,
) -> CouncilResult:
    """Run the full council: lens voices -> reconciliation -> gate -> revision.

    ``on_step(phase, detail)`` streams progress; phases are "lens", "op",
    "reconcile", "gate", "revise".
    """
    from graphify.llm import _call_llm

    unknown = [name for name in lenses if name not in LENSES]
    if unknown:
        raise ValueError(f"unknown lens(es): {', '.join(unknown)} "
                         f"(available: {', '.join(sorted(LENSES))})")

    # 1) Convene the voices. Each runs its own scoped graph-ops loop.
    reports: list[LensReport] = []
    for name in lenses:
        if on_step is not None:
            on_step("lens", name)
        answer, trace = think(
            G, question,
            backend=backend, model=model, budget=budget_per_lens,
            usage_out=usage_out, perspective=LENSES[name],
            on_step=(lambda op, res: on_step("op", f"[{name}] {op}"))
            if on_step is not None else None,
        )
        reports.append(LensReport(name=name, answer=answer,
                                  ops_used=len(trace), trace=trace))

    voiced = [r for r in reports if r.answer]
    if not voiced:
        raise RuntimeError(
            "no lens produced an answer within its op budget — raise "
            "--budget-per-lens or check the backend"
        )

    # 2) Reconcile. Only the voices' compact answers travel — never transcripts.
    if on_step is not None:
        on_step("reconcile", f"{len(voiced)} voice(s)")
    voices_text = "\n\n".join(
        f"[{r.name} voice] {r.answer}" for r in voiced
    )
    final = _call_llm(
        RECONCILE_PROMPT.format(question=question, voices=voices_text),
        backend=backend, model=model, max_tokens=500, usage_out=usage_out,
    ).strip()

    # 3) Gate + forced revision. The graph, not the model, decides what stands.
    gate_summary, gate_report, refuted = ({}, "", 0)
    revisions = 0
    if verify:
        if on_step is not None:
            on_step("gate", "checking final answer")
        gate_summary, gate_report, refuted = _gate(G, final)
        while refuted > 0 and revisions < max_revisions:
            revisions += 1
            if on_step is not None:
                on_step("revise", f"round {revisions}: {refuted} refuted claim(s)")
            final = _call_llm(
                REVISE_PROMPT.format(answer=final, gate_report=gate_report),
                backend=backend, model=model, max_tokens=500, usage_out=usage_out,
            ).strip()
            gate_summary, gate_report, refuted = _gate(G, final)

    return CouncilResult(
        question=question,
        lens_reports=reports,
        final_answer=final,
        gate_summary=gate_summary,
        gate_report=gate_report,
        revisions=revisions,
    )


def render_result(result: CouncilResult) -> str:
    lines: list[str] = []
    for r in result.lens_reports:
        status = f"{r.ops_used} op(s)" if r.answer else f"no answer in {r.ops_used} op(s)"
        lines.append(f"[{r.name} voice, {status}]")
        if r.answer:
            lines.append(f"  {r.answer}")
    lines.append("")
    lines.append(f"Consensus: {result.final_answer}")
    if result.gate_report:
        lines.append("")
        lines.append("-- hallucination gate --")
        lines.append(result.gate_report)
        if result.revisions:
            lines.append(f"(answer was revised {result.revisions} time(s) "
                         f"after refuted claims)")
    return "\n".join(lines)
