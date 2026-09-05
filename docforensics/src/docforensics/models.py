"""Core data model shared by parsers, rules and reporting.

Everything the production scanner emits is built from these records. They carry
only information obtained from the artifact bytes, ordinary static detector
resources and forensic inference — never benchmark-side truth.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ("info", "weak", "moderate", "strong")


@dataclass
class Finding:
    """One rule result.

    ``evidence`` holds raw observations (what is physically in the file);
    ``interpretation`` is the forensic reading of that evidence. Keeping the two
    apart is a hard requirement: readers must be able to see the raw fact
    without the conclusion.

    ``is_trace`` marks a finding that counts as a tamper trace for
    ``tamper_status``. Informational observations (a Software tag exists, a
    file has one revision) set it to False so they never flip the status.
    """

    rule_id: str
    family: str
    severity: str
    title: str
    evidence: dict[str, Any] = field(default_factory=dict)
    interpretation: str = ""
    confidence: float = 1.0
    is_trace: bool = True

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")
        if self.severity == "info":
            self.is_trace = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisLimit:
    """A family of analysis that could not be (fully) performed."""

    family: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"family": self.family, "reason": self.reason}


@dataclass
class RuleContext:
    """Everything a rule may look at. Populated by ``scanner.scan_bytes``.

    ``data`` is the raw artifact; ``parsed`` holds per-format parser output
    (``pdf``, ``image``, ``ooxml`` keys) or is empty when no parser applied.
    ``profiles`` is the static learned-generator store (ordinary detector
    resource). Rules never receive a path, a filename or environment data.
    """

    data: bytes
    detected_format: str
    parsed: dict[str, Any] = field(default_factory=dict)
    profiles: Any = None
    limits: list[AnalysisLimit] = field(default_factory=list)

    def limit(self, family: str, reason: str) -> None:
        self.limits.append(AnalysisLimit(family, reason))
