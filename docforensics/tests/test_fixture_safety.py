"""Out-of-band ownership, capability handles, path containment."""
import os

import pytest

from docforensics_fixtures.export import ExportError, export_artifact
from docforensics_fixtures.safety import FixtureRoot, SafetyError, contained_path


def test_rejects_traversal_and_escape(tmp_path):
    root = FixtureRoot(tmp_path / "root")
    with pytest.raises(SafetyError):
        contained_path(root.root, "../outside.bin")
    with pytest.raises(SafetyError):
        contained_path(root.root, "/etc/hostname")
    with pytest.raises(SafetyError):
        contained_path(root.root, "a/../../b")


def test_rejects_symlink_escape(tmp_path):
    root = FixtureRoot(tmp_path / "root")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.bin").write_bytes(b"x")
    link = root.root / "link"
    os.symlink(outside, link)
    with pytest.raises(SafetyError):
        contained_path(root.root, "link/x.bin")


def test_handles_are_verified_and_unregistered_sources_rejected(tmp_path):
    root = FixtureRoot(tmp_path / "root")
    rec = root.write("work/a.bin", b"hello")
    assert root.read(rec.handle) == b"hello"
    with pytest.raises(SafetyError):
        root.read("not-a-handle")
    rec.path.write_bytes(b"changed")
    with pytest.raises(SafetyError):
        root.read(rec.handle)
    # a file outside the root can never be registered
    stray = tmp_path / "stray.bin"
    stray.write_bytes(b"s")
    with pytest.raises(SafetyError):
        root.register(stray)


def test_export_refuses_directories_and_archives(bench_root, cases, tmp_path):
    cid = cases[0]["case_id"]
    with pytest.raises(ExportError):
        export_artifact(bench_root, cid, tmp_path)               # a directory
    with pytest.raises(ExportError):
        export_artifact(bench_root, cid, tmp_path / "bundle.zip")
