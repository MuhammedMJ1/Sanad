"""Case storage layout inside the fixture root (harness-internal).

    <root>/cases/<case_id>/final.bin          exact downloadable artifact bytes
    <root>/cases/<case_id>/original.bin       controlled original
    <root>/cases/<case_id>/certificate.json   external ground truth
    <root>/cases/<case_id>/record.json        harness bookkeeping (generator, content spec)

Nothing under <root> is ever visible to the scanner during evaluation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .safety import FixtureRoot, contained_path

CASES = "cases"
EVALS = "evaluations"


def make_case_id(seed: int, index: int) -> str:
    return "c" + hashlib.sha256(f"case:{seed}:{index}".encode()).hexdigest()[:10]


def pair_token(case_id: str) -> str:
    """Opaque 6-hex pairing token — derived, but encodes nothing about the case."""
    return hashlib.sha256(f"pair:{case_id}".encode()).hexdigest()[:6]


def neutral_name(case_id: str, ext: str, prefix: str = "sample") -> str:
    return f"{prefix}_{pair_token(case_id)}.{ext}"


def case_dir(root: FixtureRoot, case_id: str) -> Path:
    return contained_path(root.root, f"{CASES}/{case_id}")


def save_case(root: FixtureRoot, case_id: str, final: bytes, original: bytes,
              cert_text: str, record: dict[str, Any]) -> Path:
    d = case_dir(root, case_id)
    d.mkdir(parents=True, exist_ok=True)
    root.write(f"{CASES}/{case_id}/final.bin", final)
    root.write(f"{CASES}/{case_id}/original.bin", original)
    (d / "certificate.json").write_text(cert_text, encoding="utf-8")
    (d / "record.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return d


def load_record(root: FixtureRoot, case_id: str) -> dict[str, Any]:
    p = case_dir(root, case_id) / "record.json"
    if not p.exists():
        raise FileNotFoundError(f"unknown case {case_id}")
    return json.loads(p.read_text(encoding="utf-8"))


def load_final(root: FixtureRoot, case_id: str) -> bytes:
    return (case_dir(root, case_id) / "final.bin").read_bytes()


def load_original(root: FixtureRoot, case_id: str) -> bytes:
    return (case_dir(root, case_id) / "original.bin").read_bytes()


def load_certificate_text(root: FixtureRoot, case_id: str) -> str:
    return (case_dir(root, case_id) / "certificate.json").read_text(encoding="utf-8")


def list_cases(root: FixtureRoot) -> list[dict[str, Any]]:
    base = root.root / CASES
    if not base.exists():
        return []
    out = []
    for d in sorted(base.iterdir()):
        if (d / "record.json").exists():
            out.append(json.loads((d / "record.json").read_text(encoding="utf-8")))
    return out
