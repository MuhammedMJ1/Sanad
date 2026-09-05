"""Blind evaluation and cross-tool metrics.

Order is fixed: the scanner runs isolated on the artifact alone; only after
its process has exited is the certificate loaded and compared. The four
metrics are reported separately and never combined into one accuracy figure.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import certificate, store
from .isolation import run_isolated_scan
from .safety import FixtureRoot


def classify(cert: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Compare a detector result against certificate truth (after the fact)."""
    ts = result["tamper_status"]
    fired = set(ts.get("trace_rule_ids", []))
    expected = set(cert.get("expect_rules", []))
    gt, tc, state = cert["ground_truth"], cert["trace_class"], ts["state"]
    if gt == "unmodified":
        outcome = "false_positive" if state == "traces_found" else "true_negative"
    elif tc == "natural_trace":
        if state == "traces_found":
            outcome = "detected" if expected <= fired else "detected_partial"
        else:
            outcome = "missed_observable_evidence"
    else:  # trace_neutral, modified
        outcome = "unexpected_trace" if state == "traces_found" else "evidence_limit"
    return {
        "ground_truth": {"state": gt, "trace_class": tc, "semantic_delta": cert.get("semantic_delta"),
                         "original_sha256": cert["original"]["sha256"], "final_sha256": cert["artifact"]["final_sha256"]},
        "observable_evidence": {"expected": cert.get("expected_observable_evidence", []),
                                "expected_rules": sorted(expected)},
        "detector_inference": {"tamper_status": state, "fired_trace_rules": sorted(fired),
                               "missing_expected_rules": sorted(expected - fired)},
        "evidence_limitations": {"certified_limit": cert.get("expected_limit"),
                                 "analysis_limits": result.get("analysis_limits", [])},
        "outcome": outcome,
    }


def metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    def rate(num: int, den: int) -> float | None:
        return round(num / den, 4) if den else None
    natural = [r for r in rows if r["ground_truth"]["state"] == "modified" and r["ground_truth"]["trace_class"] == "natural_trace"]
    clean = [r for r in rows if r["ground_truth"]["state"] == "unmodified"]
    neutral = [r for r in rows if r["ground_truth"]["state"] == "modified" and r["ground_truth"]["trace_class"] == "trace_neutral"]
    detected = sum(1 for r in natural if r["outcome"] in ("detected", "detected_partial"))
    missed = sum(1 for r in natural if r["outcome"] == "missed_observable_evidence")
    fp = sum(1 for r in clean if r["outcome"] == "false_positive")
    limit = sum(1 for r in neutral if r["outcome"] == "evidence_limit")
    return {
        "natural_trace_detection_rate": {"value": rate(detected, len(natural)), "numerator": detected, "denominator": len(natural)},
        "clean_false_positive_rate": {"value": rate(fp, len(clean)), "numerator": fp, "denominator": len(clean)},
        "observable_trace_false_negative_rate": {"value": rate(missed, len(natural)), "numerator": missed, "denominator": len(natural)},
        "trace_neutral_provenance_limit_rate": {"value": rate(limit, len(neutral)), "numerator": limit, "denominator": len(neutral)},
        "note": "four independent measurements; deliberately not combined into a single accuracy figure",
    }


def evaluate(root: FixtureRoot, case_ids: list[str] | None = None, keep_workspaces: bool = False) -> dict[str, Any]:
    rows, isolation = [], []
    for rec in store.list_cases(root):
        if case_ids and rec["case_id"] not in case_ids:
            continue
        cdir = store.case_dir(root, rec["case_id"])
        # 1-7: scanner sees only the artifact copy, in its own workspace; access is logged.
        iso = run_isolated_scan(cdir / "final.bin", rec["ext"], deny_roots=[root.root], keep=keep_workspaces)
        isolation.append({"case_id": rec["case_id"], "scanned_name": iso["scanned_name"],
                          "violations": iso["violations"], "returncode": iso["returncode"],
                          "accessed_count": len(iso["accessed_paths"])})
        if iso["result"] is None:
            rows.append({"case_id": rec["case_id"], "outcome": "scanner_error", "stderr": iso["stderr"]})
            continue
        # 8: only now is the certificate opened.
        cert = certificate.loads(store.load_certificate_text(root, rec["case_id"]))
        binding = certificate.verify((cdir / "final.bin").read_bytes(), cert, (cdir / "original.bin").read_bytes())
        if not binding["certificate_valid"]:
            rows.append({"case_id": rec["case_id"], "outcome": "certificate_invalid", "binding": binding})
            continue
        if iso["result"]["input"]["sha256"] != cert["artifact"]["final_sha256"]:
            rows.append({"case_id": rec["case_id"], "outcome": "same_byte_violation"})
            continue
        row = classify(cert, iso["result"])
        row["case_id"] = rec["case_id"]
        row["scanned_name"] = iso["scanned_name"]
        rows.append(row)
    return {"cases": rows, "metrics": metrics([r for r in rows if "ground_truth" in r]), "isolation": isolation,
            "isolation_violations": sum(len(i["violations"]) for i in isolation)}


# --- external detectors ------------------------------------------------------

def record_external_result(root: FixtureRoot, case_id: str, *, name: str, version: str, result: str,
                           findings: list[Any], artifact_sha256: str) -> Path:
    """Store another tool's verdict next to (never inside) the artifact.

    Refuses to record unless the tool hashed exactly the certified bytes.
    """
    cert = certificate.loads(store.load_certificate_text(root, case_id))
    if artifact_sha256 != cert["artifact"]["final_sha256"]:
        raise ValueError("same-byte rule: detector did not analyse the certified artifact bytes")
    path = root.root / store.EVALS / f"{case_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {
        "case_id": case_id, "artifact_sha256": cert["artifact"]["final_sha256"], "detectors": []}
    doc["detectors"] = [d for d in doc["detectors"] if d["name"] != name]
    doc["detectors"].append({"name": name, "version": version, "result": result, "findings": findings})
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def compare_external(root: FixtureRoot, case_id: str) -> dict[str, Any]:
    path = root.root / store.EVALS / f"{case_id}.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    cert = certificate.loads(store.load_certificate_text(root, case_id))
    return {"case_id": case_id, "ground_truth": cert["ground_truth"], "trace_class": cert["trace_class"],
            "artifact_sha256": doc["artifact_sha256"], "detectors": doc["detectors"]}
