"""Learn generator profiles from a controlled reference corpus.

Renders ``n`` clean artifacts per generator with varied content and records
the metadata-independent structural features the production parsers
observe. The resulting store is a static detector resource; it contains
feature statistics and fictitious generator keys only — never case ids,
hashes or ground truth.
"""
from __future__ import annotations

import random
from pathlib import Path
from typing import Any

from docforensics.parsers import image as image_parser, ooxml as ooxml_parser, pdf as pdf_parser
from docforensics.structural_profile import (GeneratorProfiles, generator_key, jpeg_features,
                                             ooxml_features, pdf_features, png_features)

from . import bases


def features_for(kind: str, data: bytes) -> tuple[str, str | None, dict[str, str]]:
    if kind == "pdf":
        p = pdf_parser.parse(data)
        return "pdf", generator_key(p.get("docinfo", {}).get("/Producer")), pdf_features(p)
    if kind == "jpeg":
        p = image_parser.parse(data, "jpeg")
        make = (p.get("exif") or {}).get("ifd0", {}).get("Make")
        model = (p.get("exif") or {}).get("ifd0", {}).get("Model")
        key = (generator_key(make) or "") + ("|" + (generator_key(model) or "") if model else "") if make else None
        return "jpeg", key, jpeg_features(p)
    if kind == "png":
        p = image_parser.parse(data, "png")
        return "png", generator_key(p.get("text_chunks", {}).get("Software")), png_features(p)
    if kind == "docx":
        p = ooxml_parser.parse(data)
        return "ooxml", generator_key(p.get("app", {}).get("Application")), ooxml_features(p)
    raise ValueError(kind)


def learn_profiles(seed: int = 4242, n_per_generator: int = 8, out: Path | None = None,
                   extra_corpus: list[tuple[str, bytes]] | None = None) -> GeneratorProfiles:
    store = GeneratorProfiles({}, None)
    for gname, gen in bases.GENERATORS.items():
        for i in range(n_per_generator):
            rng = random.Random(f"learn:{seed}:{gname}:{i}")
            data = bases.render(gname, bases.make_content(gen.kind, rng))
            kind, key, feats = features_for(gen.kind, data)
            if key:
                store.learn(kind, key, feats)
    for kind, data in extra_corpus or []:
        k, key, feats = features_for(kind, data)
        if key:
            store.learn(k, key, feats)
    if out is not None:
        store.save(Path(out))
        store.source = str(out)
    return store
