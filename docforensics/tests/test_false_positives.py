"""Ordinary unmodified reference artifacts must not raise tamper findings."""
import random

import pytest

from docforensics.scanner import scan_bytes
from docforensics_fixtures import bases
from conftest import cert_of, final_of


def test_clean_controls_have_no_traces(bench_root, cases):
    for rec in cases:
        cert = cert_of(bench_root, rec["case_id"])
        if cert["ground_truth"] != "unmodified":
            continue
        res = scan_bytes(final_of(bench_root, rec["case_id"]), "sample.bin")
        traces = [f["rule_id"] for f in res["findings"] if f["is_trace"]]
        assert traces == [], f"false tamper findings on clean {rec['generator']}: {traces}"
        assert res["tamper_status"]["state"] == "no_traces_found"


@pytest.mark.parametrize("gen", sorted(bases.GENERATORS))
def test_fresh_bases_across_seeds_are_clean(gen):
    kind = bases.GENERATORS[gen].kind
    for seed in range(5):
        data = bases.render(gen, bases.make_content(kind, random.Random(f"fp:{seed}")))
        res = scan_bytes(data, "sample.bin")
        traces = [f["rule_id"] for f in res["findings"] if f["is_trace"]]
        assert traces == [], (gen, seed, traces)
