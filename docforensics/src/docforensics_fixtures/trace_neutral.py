"""Blind provenance challenges (trace_neutral).

The controlled state changes, but through the *same* generation route that
produced the original: the document is regenerated from an edited content
spec by the same writer. Nothing is planted and nothing is deliberately
retained. If that route still leaves scanner-visible residue, the build
reclassifies the case as natural_trace instead of pretending otherwise.
"""
from __future__ import annotations

import random
from typing import Any

from . import bases
from .bases import DocContent, PixelSpec
from .operations import OpResult, _new_total


def regenerate_pdf(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    doc = DocContent.from_dict(content)
    new, delta = _new_total(doc, rng)
    final = bases.render(generator, new.to_dict())
    return OpResult(final, new.to_dict(), {"kind": "text_content", "description": delta},
                    [], ["that any earlier version existed", "the previous amounts"], [],
                    f"regenerated from edited content by the same writer ({generator})")


def regenerate_image(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    spec = PixelSpec.from_dict(content)
    color = (rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255))
    box = [spec.width // 4, spec.height // 4, spec.width // 2, spec.height // 2]
    new = PixelSpec(**{**spec.to_dict(), "shapes": spec.shapes + [[*box, *color]]})
    final = bases.render(generator, new.to_dict())
    return OpResult(final, new.to_dict(), {"kind": "pixels", "description": "a region repainted, then re-captured through the same pipeline"},
                    [], ["that the scene was altered", "the previous pixels"], [],
                    f"regenerated through the same imaging pipeline ({generator})")


def regenerate_docx(original: bytes, content: dict[str, Any], generator: str, rng: random.Random) -> OpResult:
    return regenerate_pdf(original, content, generator, rng)


NEUTRAL_OPS = {
    "pdf": ("pdf.regenerate_same_writer", regenerate_pdf),
    "jpeg": ("jpeg.regenerate_same_pipeline", regenerate_image),
    "png": ("png.regenerate_same_pipeline", regenerate_image),
    "docx": ("docx.regenerate_same_writer", regenerate_docx),
}
