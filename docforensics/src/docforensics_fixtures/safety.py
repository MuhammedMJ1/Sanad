"""Out-of-band fixture ownership and path containment.

Because no marker may be embedded in an artifact, ownership is tracked
externally: every file a transformation may touch is registered in the
current run's registry and addressed by an ephemeral capability handle, never
by an arbitrary path. Registration verifies the file lives inside the run's
output root (no ``..``, no symlink escape) and records its SHA-256 so a
transformation can prove it received the bytes it was handed.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path


class SafetyError(Exception):
    """A fixture operation was asked to touch something it does not own."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class RegisteredFile:
    handle: str
    path: Path
    sha256: str
    size_bytes: int


def contained_path(root: Path, candidate: str | os.PathLike[str]) -> Path:
    """Resolve ``candidate`` and prove it lies inside ``root``.

    Rejects ``..`` components in the literal path, absolute paths outside the
    root, and symlinks (in any component) that resolve outside the root.
    """
    raw = Path(candidate)
    if any(part == ".." for part in raw.parts):
        raise SafetyError(f"path traversal rejected: {candidate}")
    root_r = root.resolve()
    target = raw if raw.is_absolute() else root_r / raw
    # Walk existing components so a symlink anywhere in the chain is resolved.
    resolved = target.resolve()
    try:
        resolved.relative_to(root_r)
    except ValueError:
        raise SafetyError(f"path escapes the fixture root: {candidate}") from None
    # A symlink inside the root that points outside is caught above; a symlink
    # that points inside is still refused for artifacts (byte identity matters).
    for parent in [target, *target.parents]:
        if parent == root_r:
            break
        if parent.is_symlink():
            raise SafetyError(f"symlink component rejected: {parent}")
    return resolved


class FixtureRoot:
    """The single directory a benchmark run may write to, plus its registry."""

    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._registry: dict[str, RegisteredFile] = {}

    # -- registry ---------------------------------------------------------
    def write(self, relpath: str, data: bytes) -> RegisteredFile:
        path = contained_path(self.root, relpath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        return self.register(path)

    def register(self, path: str | os.PathLike[str]) -> RegisteredFile:
        p = contained_path(self.root, path)
        if not p.is_file():
            raise SafetyError(f"not a regular file inside the root: {path}")
        rec = RegisteredFile(secrets.token_hex(12), p, sha256_file(p), p.stat().st_size)
        self._registry[rec.handle] = rec
        return rec

    def resolve(self, handle: str) -> RegisteredFile:
        """Look a handle up and re-verify the bytes it was registered with."""
        rec = self._registry.get(handle)
        if rec is None:
            raise SafetyError("unknown capability handle (unregistered source rejected)")
        current = sha256_file(rec.path)
        if current != rec.sha256:
            raise SafetyError(f"registered file changed on disk: {rec.path}")
        return rec

    def read(self, handle: str) -> bytes:
        return self.resolve(handle).path.read_bytes()

    def handles(self) -> list[str]:
        return list(self._registry)
