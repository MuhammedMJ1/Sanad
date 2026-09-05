"""JPEG / PNG tamper-trace rules (family ``image.tamper``)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from ..models import Finding, RuleContext
from ..structural_profile import confidence_for, generator_key, jpeg_features, png_features
from . import rule

FAMILY = "image.tamper"


def _img(ctx: RuleContext) -> dict[str, Any] | None:
    return ctx.parsed.get("image")


def _exif_tag(img: dict[str, Any], name: str) -> Any:
    ex = img.get("exif") or {}
    return (ex.get("ifd0") or {}).get(name) or (ex.get("exif") or {}).get(name)


def _camera_key(img: dict[str, Any]) -> str | None:
    make = _exif_tag(img, "Make")
    model = _exif_tag(img, "Model")
    if not make:
        return None
    k = generator_key(str(make)) or ""
    if model:
        k += "|" + (generator_key(str(model)) or "")
    return k


def _parse_exif_dt(s: Any) -> datetime | None:
    if not isinstance(s, str):
        return None
    try:
        return datetime.strptime(s.strip(), "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return None


@rule("image.tamper.software_editor_tag", family=FAMILY, formats=["jpeg", "png"],
      description="Editor/software identification present in metadata (observation only).",
      detects_trace=False)
def software_editor_tag(ctx: RuleContext) -> list[Finding]:
    img = _img(ctx)
    if not img:
        return []
    sw = _exif_tag(img, "Software") or (img.get("text_chunks") or {}).get("Software")
    if not sw:
        return []
    return [Finding("image.tamper.software_editor_tag", FAMILY, "info",
                    f"software tag present: {sw}", {"software": sw, "make": _exif_tag(img, "Make"),
                                                    "model": _exif_tag(img, "Model")},
                    "A software field identifies the last writer. On its own it is not proof of "
                    "malicious modification — cameras, phones and converters all write one.",
                    is_trace=False)]


@rule("image.tamper.exif_thumbnail_mismatch", family=FAMILY, formats=["jpeg"],
      description="Embedded EXIF thumbnail vs the full image (aspect ratio and content).")
def exif_thumbnail_mismatch(ctx: RuleContext) -> list[Finding]:
    img = _img(ctx)
    if not img:
        return []
    th = img.get("thumbnail") or {}
    if not th.get("present"):
        return []
    ev = {k: v for k, v in th.items() if k != "bytes"}
    if not th.get("in_bounds") or not th.get("valid_jpeg"):
        return [Finding("image.tamper.exif_thumbnail_mismatch", FAMILY, "moderate",
                        "EXIF thumbnail pointer is out of bounds or not a JPEG", ev,
                        "IFD1 points at a thumbnail that is truncated or invalid — typical of an "
                        "EXIF block copied into a re-encoded file without being rebuilt.")]
    sim = th.get("similarity")
    if not sim:
        return []
    if abs(sim["aspect_thumb"] - sim["aspect_main"]) > 0.05:
        return [Finding("image.tamper.exif_thumbnail_mismatch", FAMILY, "strong",
                        "EXIF thumbnail aspect ratio differs from the full image", ev,
                        "The camera-written thumbnail has a different shape than the image it is "
                        "embedded in: the image was cropped or resized after the thumbnail was made.")]
    if sim["mean_abs_diff"] > 40:
        return [Finding("image.tamper.exif_thumbnail_mismatch", FAMILY, "strong",
                        f"EXIF thumbnail content differs from the full image (mean |Δ|={sim['mean_abs_diff']})",
                        ev, "The embedded thumbnail depicts a different picture than the main image: "
                            "the pixels were changed after capture while the original thumbnail was kept.")]
    if sim["mean_abs_diff"] > 20:
        return [Finding("image.tamper.exif_thumbnail_mismatch", FAMILY, "moderate",
                        f"EXIF thumbnail only loosely matches the full image (mean |Δ|={sim['mean_abs_diff']})",
                        ev, "Moderate divergence between thumbnail and image; consistent with local "
                            "edits or heavy re-encoding after capture.")]
    return []


@rule("image.tamper.makernote_integrity", family=FAMILY, formats=["jpeg"],
      description="MakerNote and EXIF value offsets stay inside the TIFF block.")
def makernote_integrity(ctx: RuleContext) -> list[Finding]:
    img = _img(ctx)
    if not img or not img.get("has_exif"):
        return []
    mn = img.get("makernote") or {}
    problems = (img.get("exif") or {}).get("problems", [])
    if mn.get("present") and not mn.get("in_bounds"):
        return [Finding("image.tamper.makernote_integrity", FAMILY, "moderate",
                        "MakerNote points outside the EXIF block", {"makernote": mn, "problems": problems},
                        "Camera MakerNotes use absolute offsets; a re-writer that relocated or "
                        "trimmed the EXIF block leaves them dangling.")]
    if problems:
        return [Finding("image.tamper.makernote_integrity", FAMILY, "weak",
                        f"{len(problems)} EXIF offset problem(s)", {"makernote": mn, "problems": problems},
                        "Some EXIF values point beyond the TIFF data: the block was truncated or "
                        "rebuilt inconsistently.")]
    return []


@rule("image.tamper.datetime_inconsistency", family=FAMILY, formats=["jpeg", "png"],
      description="EXIF DateTime (last modification) vs DateTimeOriginal (capture).")
def datetime_inconsistency(ctx: RuleContext) -> list[Finding]:
    img = _img(ctx)
    if not img:
        return []
    dt, dto = _exif_tag(img, "DateTime"), _exif_tag(img, "DateTimeOriginal")
    a, b = _parse_exif_dt(dt), _parse_exif_dt(dto)
    if a is None or b is None:
        return []
    ev = {"DateTime": dt, "DateTimeOriginal": dto, "delta_seconds": (a - b).total_seconds()}
    if a < b:
        return [Finding("image.tamper.datetime_inconsistency", FAMILY, "moderate",
                        "DateTime is earlier than DateTimeOriginal", ev,
                        "A file cannot have been last modified before it was captured; one of the "
                        "two values was rewritten.")]
    if a > b:
        return [Finding("image.tamper.datetime_inconsistency", FAMILY, "weak",
                        "DateTime is later than DateTimeOriginal", ev,
                        "Cameras write both fields at capture; a later DateTime records a subsequent "
                        "save by other software. Weak on its own.")]
    return []


@rule("image.tamper.encoding_profile_conflict", family=FAMILY, formats=["jpeg"],
      description="JPEG container/encoding structure vs the learned profile of the claimed camera.")
def encoding_profile_conflict(ctx: RuleContext) -> list[Finding]:
    img = _img(ctx)
    if not img or ctx.profiles is None:
        return []
    gen = _camera_key(img)
    feats = jpeg_features(img)
    conflicts, n = ctx.profiles.compare("jpeg", gen, feats, ignore=("exif_present",))
    ev = {"claimed_camera": gen, "features": feats, "profile_samples": n,
          "conflicts": [c.to_dict() for c in conflicts]}
    if n == 0 or not conflicts:
        return []
    conf = confidence_for(n)
    return [Finding("image.tamper.encoding_profile_conflict", FAMILY, "moderate" if conf >= 0.6 else "weak",
                    f"{len(conflicts)} encoding feature(s) never observed for camera '{gen}' (n={n})", ev,
                    "Quantisation tables, subsampling and segment order are set by the encoder. The "
                    "file claims a camera whose measured output looks different, so the pixels were "
                    "re-encoded by other software after capture.", confidence=conf, is_trace=conf >= 0.35)]


@rule("image.tamper.png_chunk_profile_conflict", family=FAMILY, formats=["png"],
      description="PNG chunk layout vs the learned profile of the claimed Software.")
def png_chunk_profile_conflict(ctx: RuleContext) -> list[Finding]:
    img = _img(ctx)
    if not img or ctx.profiles is None:
        return []
    gen = generator_key((img.get("text_chunks") or {}).get("Software"))
    feats = png_features(img)
    conflicts, n = ctx.profiles.compare("png", gen, feats)
    if n == 0 or not conflicts:
        return []
    conf = confidence_for(n)
    return [Finding("image.tamper.png_chunk_profile_conflict", FAMILY, "moderate" if conf >= 0.6 else "weak",
                    f"{len(conflicts)} chunk-layout feature(s) never observed for '{gen}' (n={n})",
                    {"claimed_software": gen, "features": feats, "profile_samples": n,
                     "conflicts": [c.to_dict() for c in conflicts]},
                    "The Software text chunk claims one writer but the chunk order/ancillary chunks "
                    "match a different encoder: the image was re-saved by other software while the "
                    "old text chunk was carried over.", confidence=conf, is_trace=conf >= 0.35)]


@rule("image.tamper.png_chunk_integrity", family=FAMILY, formats=["png"],
      description="PNG chunk CRC integrity.")
def png_chunk_integrity(ctx: RuleContext) -> list[Finding]:
    img = _img(ctx)
    if not img:
        return []
    bad = [p for p in img.get("problems", []) if "CRC" in p]
    if not bad:
        return []
    return [Finding("image.tamper.png_chunk_integrity", FAMILY, "moderate",
                    f"{len(bad)} chunk(s) with CRC mismatch", {"problems": bad},
                    "Encoders always write valid CRCs; a mismatch means bytes were patched in place "
                    "after encoding.")]
