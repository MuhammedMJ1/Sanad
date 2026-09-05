"""Shared fixtures: one blind benchmark built per session, evaluated once."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from docforensics_fixtures import certificate, store
from docforensics_fixtures.build import build
from docforensics_fixtures.safety import FixtureRoot

SEED = 2024


@pytest.fixture(scope="session")
def bench_root(tmp_path_factory) -> FixtureRoot:
    root = FixtureRoot(tmp_path_factory.mktemp("bench"))
    build(root, "all", seed=SEED, per_generator=1)
    return root


@pytest.fixture(scope="session")
def cases(bench_root) -> list[dict]:
    return store.list_cases(bench_root)


@pytest.fixture(scope="session")
def eval_report(bench_root) -> dict:
    from docforensics_fixtures.benchmark import evaluate
    return evaluate(bench_root)


def cert_of(root: FixtureRoot, case_id: str) -> dict:
    return certificate.loads(store.load_certificate_text(root, case_id))


def final_of(root: FixtureRoot, case_id: str) -> bytes:
    return store.load_final(root, case_id)


def original_of(root: FixtureRoot, case_id: str) -> bytes:
    return store.load_original(root, case_id)


def row_of(report: dict, case_id: str) -> dict:
    return next(r for r in report["cases"] if r["case_id"] == case_id)
