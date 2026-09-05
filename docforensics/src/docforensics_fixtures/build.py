"""Blind benchmark construction: bases -> controlled operations -> certificates."""
from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Any

from docforensics.signatures import identify

from . import bases, certificate, store
from .disclosure import find_disclosures
from .operations import OpResult, operations_for
from .safety import FixtureRoot, sha256_bytes
from .trace_neutral import NEUTRAL_OPS

TRACE_CLASSES = ("natural_trace", "trace_neutral", "all")


class DisclosureError(Exception):
    pass


def _residue_check(final: bytes) -> list[str]:
    """Harness-side: which trace rules fire on the final bytes (in-process)."""
    from docforensics.scanner import scan_bytes
    res = scan_bytes(final, "sample.bin")
    return sorted({f["rule_id"] for f in res["findings"] if f["is_trace"]})


def _save(root: FixtureRoot, case_id: str, gen: bases.Generator, generator: str, original: bytes,
          final: bytes, base_content: dict[str, Any], content: dict[str, Any], *, ground_truth: str,
          trace_class: str, ops: list[dict[str, str]], semantic_delta: dict[str, str],
          observable: list[str], unobservable: list[str], expect_rules: list[str],
          expect_status: str, expected_limit: str | None, notes: str, seed: int, now: str) -> dict[str, Any]:
    download_name = store.neutral_name(case_id, gen.ext)
    fmt = identify(final).detected_format
    cert = certificate.build(
        case_id=case_id, download_name=download_name, final_bytes=final, original_bytes=original,
        detected_format=fmt, ground_truth=ground_truth, trace_class=trace_class,
        controlled_operations=ops, semantic_delta=semantic_delta,
        expected_observable_evidence=observable, expected_unobservable_ground_truth=unobservable,
        expect_rules=expect_rules, expect_tamper_status=expect_status, expected_limit=expected_limit,
        notes=notes, generated_at=now,
    )
    # Refusal gate: the artifact must not carry any harness disclosure.
    hits = find_disclosures(final, fmt, extra_tokens=[case_id, cert["artifact"]["final_sha256"],
                                                      cert["original"]["sha256"], *[o["operation_id"] for o in ops]])
    if hits:
        raise DisclosureError(f"artifact for {case_id} carries harness disclosure: {hits[:3]}")
    record = {
        "case_id": case_id, "kind": gen.kind, "generator": generator, "ext": gen.ext,
        "download_name": download_name, "trace_class": trace_class, "ground_truth": ground_truth,
        "operation_ids": [o["operation_id"] for o in ops], "base_content": base_content, "content": content,
        "final_sha256": sha256_bytes(final), "original_sha256": sha256_bytes(original),
        "seed": seed, "created_at": now, "detected_format": fmt,
    }
    store.save_case(root, case_id, final, original, certificate.dumps(cert), record)
    return record


def build(root: FixtureRoot, trace_class: str = "all", seed: int = 1337, per_generator: int = 1,
          generators: list[str] | None = None) -> list[dict[str, Any]]:
    if trace_class not in TRACE_CLASSES:
        raise ValueError(f"trace_class must be one of {TRACE_CLASSES}")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    records: list[dict[str, Any]] = []
    index = 0
    want_natural = trace_class in ("natural_trace", "all")
    want_neutral = trace_class in ("trace_neutral", "all")
    for gname in generators or list(bases.GENERATORS):
        gen = bases.GENERATORS[gname]
        for i in range(per_generator):
            rng = random.Random(f"{seed}:{gname}:{i}")
            base_content = bases.make_content(gen.kind, rng)
            original = bases.render(gname, base_content)
            base_rec = root.write(f"work/{gname}-{i}.bin", original)   # registered, owned by this run
            # 1. unmodified control
            case_id = store.make_case_id(seed, index); index += 1
            records.append(_save(root, case_id, gen, gname, original, original, base_content, base_content,
                                 ground_truth="unmodified", trace_class="trace_neutral", ops=[],
                                 semantic_delta={"kind": "none", "description": "unmodified control"},
                                 observable=[], unobservable=[], expect_rules=[],
                                 expect_status="no_traces_found", expected_limit=None,
                                 notes="clean reference artifact; any trace finding is a false positive",
                                 seed=seed, now=now))
            # 2. natural-trace operations
            if want_natural:
                for op in operations_for(gen.kind, gname):
                    src = root.read(base_rec.handle)          # capability handle, sha re-verified
                    res: OpResult = op.fn(src, base_content, gname, random.Random(f"{seed}:{gname}:{i}:{op.op_id}"))
                    case_id = store.make_case_id(seed, index); index += 1
                    records.append(_save(root, case_id, gen, gname, src, res.final, base_content, res.content,
                                         ground_truth="modified", trace_class="natural_trace",
                                         ops=[{"operation_id": op.op_id, "description": op.description}],
                                         semantic_delta=res.semantic_delta, observable=res.expected_observable_evidence,
                                         unobservable=res.expected_unobservable_ground_truth,
                                         expect_rules=res.expect_rules, expect_status="traces_found",
                                         expected_limit=None, notes=res.description, seed=seed, now=now))
            # 3. trace-neutral challenge
            if want_neutral:
                op_id, fn = NEUTRAL_OPS[gen.kind]
                src = root.read(base_rec.handle)
                res = fn(src, base_content, gname, random.Random(f"{seed}:{gname}:{i}:{op_id}"))
                residue = _residue_check(res.final)
                case_id = store.make_case_id(seed, index); index += 1
                if residue:
                    tc, status, limit = "natural_trace", "traces_found", None
                    notes = (f"{res.description}; reclassified to natural_trace because the ordinary "
                             f"generation route left scanner-visible residue: {residue}")
                    observable = [f"residue observed at build time: {r}" for r in residue]
                else:
                    tc, status, limit = "trace_neutral", "no_traces_found", certificate.EVIDENCE_LIMIT
                    notes = res.description + "; no scanner-observable residue expected — evidence limit"
                    observable = []
                records.append(_save(root, case_id, gen, gname, src, res.final, base_content, res.content,
                                     ground_truth="modified", trace_class=tc,
                                     ops=[{"operation_id": op_id, "description": res.description}],
                                     semantic_delta=res.semantic_delta, observable=observable,
                                     unobservable=res.expected_unobservable_ground_truth,
                                     expect_rules=[], expect_status=status, expected_limit=limit,
                                     notes=notes, seed=seed, now=now))
    return records
