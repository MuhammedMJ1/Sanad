"""``docforensics scan FILE [--json -|PATH] [--html PATH]``"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def _summary(res: dict[str, Any]) -> str:
    inp, ts = res["input"], res["tamper_status"]
    lines = [
        f"file: {inp['name']}  ({inp['size_bytes']} bytes, sha256 {inp['sha256'][:16]}…)",
        f"format: {inp['detected_format']}  [{inp['format_evidence']}]"
        + (f"  extension hint: {inp['extension_hint']}" if inp["extension_hint"] else ""),
        f"tamper_status: {ts['state']}",
        f"  {ts['explanation_ar']}",
        f"  {ts['explanation_en']}",
    ]
    if res["findings"]:
        lines.append(f"findings ({len(res['findings'])}):")
        for f in res["findings"]:
            mark = "*" if f["is_trace"] else "-"
            lines.append(f"  {mark} [{f['severity']}] {f['rule_id']}: {f['title']}")
    if res["analysis_limits"]:
        lines.append("analysis_limits:")
        for l in res["analysis_limits"]:
            lines.append(f"  - {l['family']}: {l['reason']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="docforensics", description="Read-only document tamper-trace scanner.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="analyse one file (any format, any extension, read-only)")
    s.add_argument("file")
    s.add_argument("--json", metavar="PATH", help="write JSON result to PATH, or '-' for stdout")
    s.add_argument("--html", metavar="PATH", help="write an HTML report to PATH")
    s.add_argument("--profiles", metavar="PATH", help="alternative learned-generator profile store")
    args = parser.parse_args(argv)

    from .scanner import scan_file
    from .structural_profile import GeneratorProfiles
    from pathlib import Path

    profiles = GeneratorProfiles.load(Path(args.profiles)) if args.profiles else None
    try:
        res = scan_file(args.file, profiles)
    except FileNotFoundError:
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 2
    except IsADirectoryError:
        print(f"error: is a directory: {args.file}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"error: cannot read: {exc}", file=sys.stderr)
        return 2

    if args.html:
        from .report import render_html
        Path(args.html).write_text(render_html(res), encoding="utf-8")
    if args.json == "-":
        json.dump(res, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    elif args.json:
        Path(args.json).write_text(json.dumps(res, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        print(_summary(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
