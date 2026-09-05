"""Scanner workspace isolation.

The production scanner runs in a separate subprocess that receives exactly one
thing: a copy of the final artifact under a neutral random filename inside a
scratch workspace. The environment is scrubbed, and a Python audit hook logs
every ``open`` the process performs so the harness can prove afterwards that
nothing under the benchmark root (certificates, originals, registry) was
read. The certificate is loaded only after the subprocess has exited.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

FORBIDDEN_ENV_PREFIXES = ("DOCFORENSICS_", "FIXTURE", "BENCH", "CASE_", "CERT")
FORBIDDEN_NAME_PARTS = ("tamper", "modified", "clean", "forged", "reconciled", "neutral", "fixture",
                        "case", "cert", "ground", "truth", "original", "adversarial", "docinfo")

_CHILD = r"""
import sys, json, os
LOG, RESULT, ARTIFACT = sys.argv[1], sys.argv[2], sys.argv[3]
_log = open(LOG, "a", encoding="utf-8")
def _hook(event, args):
    if event == "open":
        try:
            _log.write(json.dumps({"event": "open", "path": str(args[0]), "mode": str(args[1])}) + "\n")
            _log.flush()
        except Exception:
            pass
sys.addaudithook(_hook)
from docforensics.scanner import scan_file
res = scan_file(ARTIFACT)
with open(RESULT, "w", encoding="utf-8") as fh:
    json.dump(res, fh, ensure_ascii=False)
"""


def neutral_scan_name(ext: str) -> str:
    """Random opaque name: encodes nothing about the case."""
    return f"sample_{secrets.token_hex(3)}.{ext}"


def clean_env(workspace: Path) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(workspace),
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONIOENCODING": "utf-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for key in ("PYTHONPATH", "VIRTUAL_ENV", "SYSTEMROOT", "TEMP", "TMP"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def run_isolated_scan(artifact_path: Path, ext: str, deny_roots: list[Path],
                      workspace: Path | None = None, keep: bool = False) -> dict[str, Any]:
    ws = Path(workspace) if workspace else Path(tempfile.mkdtemp(prefix="dfws-"))
    ws.mkdir(parents=True, exist_ok=True)
    for root in deny_roots:
        try:
            ws.resolve().relative_to(Path(root).resolve())
            raise ValueError("workspace must not live inside a denied root")
        except ValueError as exc:
            if "workspace must not" in str(exc):
                raise
    name = neutral_scan_name(ext)
    target = ws / name
    shutil.copyfile(artifact_path, target)      # bytes only; no metadata, no certificate
    log, result = ws / "access.log", ws / "result.json"
    env = clean_env(ws)
    proc = subprocess.run([sys.executable, "-c", _CHILD, str(log), str(result), str(target)],
                          env=env, capture_output=True, text=True, timeout=300)
    accessed: list[dict[str, Any]] = []
    if log.exists():
        for line in log.read_text(encoding="utf-8").splitlines():
            try:
                accessed.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    violations = find_violations(accessed, deny_roots, exclude=[log, result])
    out = {
        "scanned_name": name, "returncode": proc.returncode, "stderr": proc.stderr[-2000:],
        "result": json.loads(result.read_text(encoding="utf-8")) if result.exists() else None,
        "accessed_paths": [a["path"] for a in accessed], "violations": violations,
        "env_keys": sorted(env.keys()), "workspace": str(ws),
    }
    if not keep:
        shutil.rmtree(ws, ignore_errors=True)
    return out


def find_violations(accessed: list[dict[str, Any]], deny_roots: list[Path],
                    exclude: list[Path] = ()) -> list[dict[str, Any]]:
    """Which logged opens touched a denied root or a ground-truth file."""
    deny = [Path(r).resolve() for r in deny_roots]
    excluded = {Path(e).resolve() for e in exclude}
    violations = []
    for a in accessed:
        p = Path(a["path"])
        try:
            rp = p.resolve()
        except OSError:
            rp = p
        if rp in excluded:
            continue
        hit = False
        for d in deny:
            try:
                rp.relative_to(d)
                hit = True
                break
            except ValueError:
                continue
        lname = p.name.lower()
        if lname in ("certificate.json", "original.bin", "record.json") or "certificate" in lname:
            hit = True
        if hit:
            violations.append(a)
    return violations


def env_discloses(env: dict[str, str], forbidden_values: list[str]) -> list[str]:
    bad = [k for k in env if k.upper().startswith(FORBIDDEN_ENV_PREFIXES)]
    for k, v in env.items():
        if any(fv and fv in v for fv in forbidden_values):
            bad.append(k)
    return sorted(set(bad))


def name_discloses(name: str) -> list[str]:
    low = name.lower()
    return [p for p in FORBIDDEN_NAME_PARTS if p in low]
