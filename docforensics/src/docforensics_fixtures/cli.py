"""``docforensics-fixtures`` — harness-only interface (never fed to the scanner)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .safety import FixtureRoot, SafetyError


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="docforensics-fixtures", description="Blind benchmark construction for DocForensics.")
    p.add_argument("--root", default="./docforensics-bench", help="fixture root (all outputs are contained here)")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="build controlled cases")
    b.add_argument("--trace-class", choices=["natural_trace", "trace_neutral", "all"], default="all")
    b.add_argument("--seed", type=int, default=1337)
    b.add_argument("--per-generator", type=int, default=1)
    b.add_argument("--generators", help="comma-separated subset of generators")

    sub.add_parser("list", help="list controlled cases (harness view)")

    e = sub.add_parser("export", help="export artifact AND certificate as two independent files")
    e.add_argument("case"); e.add_argument("--artifact-out", required=True); e.add_argument("--certificate-out", required=True)
    ea = sub.add_parser("export-artifact", help="export only the artifact"); ea.add_argument("case"); ea.add_argument("--out", required=True)
    ec = sub.add_parser("export-certificate", help="export only the certificate"); ec.add_argument("case"); ec.add_argument("--out", required=True)

    v = sub.add_parser("verify-certificate", help="recompute the hash binding of an artifact/certificate pair")
    v.add_argument("--artifact", required=True); v.add_argument("--certificate", required=True)
    v.add_argument("--original", help="optional stored controlled original to check original.sha256")

    lp = sub.add_parser("learn-profiles", help="measure generator profiles from the controlled reference corpus")
    lp.add_argument("--out", required=True); lp.add_argument("--seed", type=int, default=4242); lp.add_argument("--n", type=int, default=8)

    ev = sub.add_parser("evaluate", help="blind evaluation: isolated scans, then certificate comparison")
    ev.add_argument("--cases", help="comma-separated case ids"); ev.add_argument("--json", metavar="PATH")

    si = sub.add_parser("scan-isolated", help="run the production scanner on one case in an isolated workspace")
    si.add_argument("case"); si.add_argument("--json", metavar="PATH")

    rx = sub.add_parser("record-external", help="record another detector's result for a case (same-byte rule enforced)")
    rx.add_argument("case"); rx.add_argument("--name", required=True); rx.add_argument("--version", required=True)
    rx.add_argument("--result", required=True); rx.add_argument("--artifact-sha256", required=True)
    rx.add_argument("--findings-json", help="path to a JSON list of findings")

    args = p.parse_args(argv)
    try:
        return _dispatch(args)
    except SafetyError as exc:
        print(f"safety: {exc}", file=sys.stderr)
        return 3


def _dispatch(args: argparse.Namespace) -> int:
    from . import store
    root = FixtureRoot(args.root)
    if args.cmd == "build":
        from .build import build
        gens = args.generators.split(",") if args.generators else None
        recs = build(root, args.trace_class, args.seed, args.per_generator, gens)
        for r in recs:
            print(f"{r['case_id']}  {r['kind']:<5} {r['generator']:<12} {r['ground_truth']:<10} {r['trace_class']:<14} {','.join(r['operation_ids']) or '-'}")
        print(f"{len(recs)} case(s) under {root.root}")
        return 0
    if args.cmd == "list":
        for r in store.list_cases(root):
            print(f"{r['case_id']}  {r['kind']:<5} {r['generator']:<12} {r['ground_truth']:<10} {r['trace_class']:<14} {r['download_name']}  {','.join(r['operation_ids']) or '-'}")
        return 0
    if args.cmd in ("export", "export-artifact", "export-certificate"):
        from .export import ExportError, export_artifact, export_certificate, export_both
        try:
            if args.cmd == "export":
                out = export_both(root, args.case, Path(args.artifact_out), Path(args.certificate_out))
            elif args.cmd == "export-artifact":
                out = export_artifact(root, args.case, Path(args.out))
            else:
                out = export_certificate(root, args.case, Path(args.out))
        except ExportError as exc:
            print(f"export: {exc}", file=sys.stderr)
            return 4
        print(json.dumps(out, indent=2))
        return 0
    if args.cmd == "verify-certificate":
        from . import certificate
        cert = certificate.loads(Path(args.certificate).read_text(encoding="utf-8"))
        original = Path(args.original).read_bytes() if args.original else None
        res = certificate.verify(Path(args.artifact).read_bytes(), cert, original)
        for k in ("artifact_hash_match", "original_hash_match", "integrity_valid", "certificate_valid"):
            print(f"{k}: {str(res[k]).lower()}")
        for r in res["reasons"]:
            print(f"reason: {r}")
        return 0 if res["certificate_valid"] else 5
    if args.cmd == "learn-profiles":
        from .learn import learn_profiles
        prof = learn_profiles(args.seed, args.n, Path(args.out))
        for kind, gens in sorted(prof.store.items()):
            for g, rec in sorted(gens.items()):
                print(f"{kind:<6} {g:<24} n={rec['n']}")
        return 0
    if args.cmd == "evaluate":
        from .benchmark import evaluate
        rep = evaluate(root, args.cases.split(",") if args.cases else None)
        if args.json:
            Path(args.json).write_text(json.dumps(rep, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        for row in rep["cases"]:
            gt = row.get("ground_truth", {})
            print(f"{row['case_id']}  {gt.get('state', '?'):<10} {gt.get('trace_class', '?'):<14} -> "
                  f"{row.get('detector_inference', {}).get('tamper_status', '?'):<20} {row['outcome']}")
        print("metrics:")
        for k, v in rep["metrics"].items():
            if isinstance(v, dict):
                print(f"  {k}: {v['value']}  ({v['numerator']}/{v['denominator']})")
        print(f"isolation violations: {rep['isolation_violations']}")
        return 0 if rep["isolation_violations"] == 0 else 6
    if args.cmd == "scan-isolated":
        from .isolation import run_isolated_scan
        rec = store.load_record(root, args.case)
        iso = run_isolated_scan(store.case_dir(root, args.case) / "final.bin", rec["ext"], [root.root])
        out = {k: iso[k] for k in ("scanned_name", "returncode", "violations", "env_keys")}
        out["accessed_paths"] = iso["accessed_paths"]
        out["result"] = iso["result"]
        if args.json:
            Path(args.json).write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({k: out[k] for k in ("scanned_name", "violations", "env_keys")}, indent=2))
        if iso["result"]:
            print(json.dumps(iso["result"]["tamper_status"], ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "record-external":
        from .benchmark import record_external_result
        findings = json.loads(Path(args.findings_json).read_text(encoding="utf-8")) if args.findings_json else []
        try:
            path = record_external_result(root, args.case, name=args.name, version=args.version, result=args.result,
                                          findings=findings, artifact_sha256=args.artifact_sha256)
        except ValueError as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 7
        print(str(path))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
