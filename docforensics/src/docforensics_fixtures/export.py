"""Independent downloads: the artifact and the certificate are two files.

* ``export_artifact`` writes the stored bytes verbatim to a *file* path and
  proves it by re-hashing the written file. It never reads the certificate.
* ``export_certificate`` writes the stored certificate text verbatim. It never
  touches the artifact.
* No archive, bundle or folder export exists.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from . import store
from .safety import FixtureRoot

ARCHIVE_SUFFIXES = {".zip", ".tar", ".tgz", ".gz", ".7z", ".rar", ".bz2", ".xz"}


class ExportError(Exception):
    pass


def _check_out(out: Path) -> Path:
    out = Path(out)
    if out.exists() and out.is_dir():
        raise ExportError(f"--out must be a file path, not a directory: {out}")
    if out.suffix.lower() in ARCHIVE_SUFFIXES:
        raise ExportError("archives are not an export format: artifact and certificate are separate files")
    out.parent.mkdir(parents=True, exist_ok=True)
    return out


def export_artifact(root: FixtureRoot, case_id: str, out: Path) -> dict[str, Any]:
    out = _check_out(out)
    data = store.load_final(root, case_id)
    rec = store.load_record(root, case_id)
    with open(out, "wb") as fh:
        fh.write(data)
    written = hashlib.sha256(out.read_bytes()).hexdigest()
    if written != rec["final_sha256"]:
        raise ExportError("exported artifact bytes differ from the stored artifact")
    return {"path": str(out), "sha256": written, "size_bytes": len(data)}


def export_certificate(root: FixtureRoot, case_id: str, out: Path) -> dict[str, Any]:
    out = _check_out(out)
    text = store.load_certificate_text(root, case_id)
    out.write_text(text, encoding="utf-8")
    return {"path": str(out), "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "size_bytes": len(text.encode("utf-8"))}


def export_both(root: FixtureRoot, case_id: str, artifact_out: Path, certificate_out: Path) -> dict[str, Any]:
    if Path(artifact_out).resolve() == Path(certificate_out).resolve():
        raise ExportError("artifact and certificate must be two different files")
    return {"artifact": export_artifact(root, case_id, artifact_out),
            "certificate": export_certificate(root, case_id, certificate_out)}
