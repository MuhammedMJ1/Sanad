"""Rule registry.

A rule is a plain function ``(ctx: RuleContext) -> list[Finding]`` registered
with :func:`rule`. ``formats`` names the detected formats it applies to; the
scanner only runs rules whose format matches, so a rule never has to guard
against foreign input. Families group rules for ``analysis_limits`` reporting.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from ..models import Finding, RuleContext

RuleFn = Callable[[RuleContext], "list[Finding]"]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    family: str
    formats: frozenset[str]
    fn: RuleFn
    description: str
    detects_trace: bool = True   # False for purely informational rules


_REGISTRY: dict[str, Rule] = {}


def rule(rule_id: str, *, family: str, formats: Iterable[str], description: str = "",
         detects_trace: bool = True) -> Callable[[RuleFn], RuleFn]:
    def deco(fn: RuleFn) -> RuleFn:
        if rule_id in _REGISTRY:
            raise ValueError(f"duplicate rule id {rule_id}")
        _REGISTRY[rule_id] = Rule(rule_id, family, frozenset(formats), fn,
                                  description or (fn.__doc__ or "").strip(), detects_trace)
        return fn
    return deco


def _load_builtin() -> None:
    # Imported lazily so the registry is complete on first use without
    # import-cycle games.
    from . import pdf_tamper, image_tamper, ooxml_tamper  # noqa: F401


def all_rules() -> list[Rule]:
    _load_builtin()
    return sorted(_REGISTRY.values(), key=lambda r: r.rule_id)


def rules_for(detected_format: str) -> list[Rule]:
    return [r for r in all_rules() if detected_format in r.formats]


def run_rules(ctx: RuleContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in rules_for(ctx.detected_format):
        try:
            findings.extend(r.fn(ctx))
        except Exception as exc:  # a broken rule must not kill the scan
            ctx.limit(r.family, f"rule {r.rule_id} failed: {type(exc).__name__}: {exc}")
    return findings
