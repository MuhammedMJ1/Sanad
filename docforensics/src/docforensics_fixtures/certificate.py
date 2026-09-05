"""External JSON ground-truth certificates.

A certificate is the *only* place benchmark truth lives. It binds itself to
the exact artifact bytes (``artifact.final_sha256``) and to the controlled
original (``original.sha256``). An ``integrity`` digest over the canonical
certificate body makes field mutation detectable.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

CERTIFICATE_VERSION = 1
EVIDENCE_LIMIT = "provenance_not_establishable_from_file_alone"


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def integrity_digest(cert: dict[str, Any]) -> str:
    body = {k: v for k, v in cert.items() if k != "integrity"}
    return hashlib.sha256(canonical(body)).hexdigest()


def build(*, case_id: str, download_name: str, final_bytes: bytes, original_bytes: bytes,
          detected_format: str, ground_truth: str, trace_class: str,
          controlled_operations: list[dict[str, str]], semantic_delta: dict[str, str],
          expected_observable_evidence: list[str], expected_unobservable_ground_truth: list[str],
          expect_rules: list[str], expect_tamper_status: str, expected_limit: str | None,
          notes: str = "", generated_at: str | None = None) -> dict[str, Any]:
    if ground_truth not in ("modified", "unmodified"):
        raise ValueError("ground_truth must be modified|unmodified")
    if trace_class not in ("natural_trace", "trace_neutral"):
        raise ValueError("trace_class must be natural_trace|trace_neutral")
    cert: dict[str, Any] = {
        "certificate_version": CERTIFICATE_VERSION,
        "case_id": case_id,
        "artifact": {
            "download_name": download_name,
            "final_sha256": hashlib.sha256(final_bytes).hexdigest(),
            "size_bytes": len(final_bytes),
            "detected_format": detected_format,
        },
        "original": {
            "sha256": hashlib.sha256(original_bytes).hexdigest(),
            "size_bytes": len(original_bytes),
        },
        "ground_truth": ground_truth,
        "trace_class": trace_class,
        "controlled_operations": controlled_operations,
        "semantic_delta": semantic_delta,
        "expected_observable_evidence": expected_observable_evidence,
        "expected_unobservable_ground_truth": expected_unobservable_ground_truth,
        "expect_rules": expect_rules,
        "expect_tamper_status": expect_tamper_status,
        "expected_limit": expected_limit,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "notes": notes,
    }
    cert["integrity"] = {"algorithm": "sha256", "digest": integrity_digest(cert)}
    return cert


def dumps(cert: dict[str, Any]) -> str:
    return json.dumps(cert, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def loads(text: str) -> dict[str, Any]:
    return json.loads(text)


def verify(artifact_bytes: bytes, cert: dict[str, Any], original_bytes: bytes | None = None) -> dict[str, Any]:
    """Recompute every binding. Refuses comparison when the artifact hash differs."""
    out: dict[str, Any] = {
        "artifact_hash_match": False, "original_hash_match": None, "integrity_valid": False,
        "certificate_valid": False, "reasons": [],
    }
    try:
        expected = cert["artifact"]["final_sha256"]
        expected_size = int(cert["artifact"]["size_bytes"])
    except (KeyError, TypeError, ValueError):
        out["reasons"].append("certificate lacks artifact binding")
        return out
    actual = hashlib.sha256(artifact_bytes).hexdigest()
    out["artifact_sha256"] = actual
    out["artifact_hash_match"] = actual == expected and len(artifact_bytes) == expected_size
    if not out["artifact_hash_match"]:
        out["reasons"].append("artifact bytes do not match certificate.artifact.final_sha256 — comparison refused")
    integ = cert.get("integrity") or {}
    out["integrity_valid"] = integ.get("algorithm") == "sha256" and integ.get("digest") == integrity_digest(cert)
    if not out["integrity_valid"]:
        out["reasons"].append("certificate integrity digest does not match its body")
    if original_bytes is not None:
        out["original_hash_match"] = hashlib.sha256(original_bytes).hexdigest() == cert.get("original", {}).get("sha256")
        if not out["original_hash_match"]:
            out["reasons"].append("stored controlled original does not match certificate.original.sha256")
    out["certificate_valid"] = bool(out["artifact_hash_match"] and out["integrity_valid"]
                                    and out["original_hash_match"] is not False)
    return out
