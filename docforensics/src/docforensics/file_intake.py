"""Universal read-only intake for ``docforensics scan``.

Accepts any user-supplied path. The file is opened once, read-only, in binary
mode; nothing is ever written next to it or into it. All later analysis works
on the in-memory bytes, which is what makes the read-only guarantee
enforceable (SHA-256 before == SHA-256 after).
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from .signatures import Signature, identify, extension_hint, EXPECTED_EXTENSIONS


@dataclass(frozen=True)
class Intake:
    path: str
    name: str
    size_bytes: int
    sha256: str
    data: bytes
    signature: Signature
    extension: str | None
    extension_agrees: bool | None   # None when format has no expected extension

    @property
    def detected_format(self) -> str:
        return self.signature.detected_format


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def intake_bytes(data: bytes, name: str = "<bytes>", path: str = "") -> Intake:
    sig = identify(data)
    ext = extension_hint(name)
    expected = EXPECTED_EXTENSIONS.get(sig.detected_format)
    agrees: bool | None
    if expected is None or ext is None:
        agrees = None
    else:
        agrees = ext in expected
    return Intake(
        path=path, name=name, size_bytes=len(data), sha256=sha256_bytes(data),
        data=data, signature=sig, extension=ext, extension_agrees=agrees,
    )


def intake_file(path: str | os.PathLike[str]) -> Intake:
    """Read ``path`` read-only. Raises FileNotFoundError / IsADirectoryError."""
    p = Path(path)
    if p.is_dir():
        raise IsADirectoryError(str(p))
    with open(p, "rb") as fh:          # binary, read-only; never "r+"/"a"
        data = fh.read()
    return intake_bytes(data, name=p.name, path=str(p))
