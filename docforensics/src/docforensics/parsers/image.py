"""JPEG / PNG parser with a self-contained EXIF (TIFF) reader.

Pillow decodes pixels; the container walk (APP segments, DQT, SOF, EXIF IFDs,
MakerNote bounds, IFD1 thumbnail) is done here so offsets and structure are
reported exactly as they are in the file.
"""
from __future__ import annotations

import hashlib
import io
import struct
import zlib
from typing import Any

TAGS = {
    0x010F: "Make", 0x0110: "Model", 0x0131: "Software", 0x0132: "DateTime",
    0x0112: "Orientation", 0x011A: "XResolution", 0x011B: "YResolution",
    0x8769: "ExifIFDPointer", 0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
    0x927C: "MakerNote", 0xA002: "PixelXDimension", 0xA003: "PixelYDimension",
    0x0201: "JPEGInterchangeFormat", 0x0202: "JPEGInterchangeFormatLength",
    0x0100: "ImageWidth", 0x0101: "ImageLength", 0x0103: "Compression",
    0x8825: "GPSInfoIFDPointer", 0x9000: "ExifVersion", 0xA000: "FlashpixVersion",
    0xA300: "FileSource", 0xA301: "SceneType", 0x013B: "Artist", 0x8298: "Copyright",
}
TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}


def _read_ifd(tiff: bytes, offset: int, endian: str) -> tuple[dict[str, Any], int | None, list[str]]:
    """Return ({tag_name: value}, next_ifd_offset, problems)."""
    problems: list[str] = []
    entries: dict[str, Any] = {}
    if offset + 2 > len(tiff):
        return entries, None, ["ifd offset beyond TIFF data"]
    (count,) = struct.unpack(endian + "H", tiff[offset:offset + 2])
    pos = offset + 2
    for _ in range(count):
        if pos + 12 > len(tiff):
            problems.append("ifd entry truncated")
            break
        tag, typ, cnt = struct.unpack(endian + "HHI", tiff[pos:pos + 8])
        size = TYPE_SIZES.get(typ, 1) * cnt
        if size <= 4:
            raw = tiff[pos + 8:pos + 8 + size]
            voff = pos + 8
        else:
            (voff,) = struct.unpack(endian + "I", tiff[pos + 8:pos + 12])
            raw = tiff[voff:voff + size]
            if voff + size > len(tiff):
                problems.append(f"tag 0x{tag:04X} value offset {voff}+{size} beyond TIFF data ({len(tiff)})")
        name = TAGS.get(tag, f"0x{tag:04X}")
        if typ == 2:
            val: Any = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
        elif typ in (3, 8):
            fmt = "H" if typ == 3 else "h"
            val = list(struct.unpack(endian + fmt * cnt, raw)) if len(raw) == 2 * cnt else None
            if val is not None and cnt == 1:
                val = val[0]
        elif typ in (4, 9):
            fmt = "I" if typ == 4 else "i"
            val = list(struct.unpack(endian + fmt * cnt, raw)) if len(raw) == 4 * cnt else None
            if val is not None and cnt == 1:
                val = val[0]
        elif typ == 7:
            val = {"undefined_len": cnt, "offset": voff, "in_bounds": voff + size <= len(tiff)}
        else:
            val = {"type": typ, "count": cnt, "offset": voff}
        entries[name] = val
        pos += 12
    nxt = None
    if pos + 4 <= len(tiff):
        (nxt,) = struct.unpack(endian + "I", tiff[pos:pos + 4])
        nxt = nxt or None
    return entries, nxt, problems


def parse_exif(payload: bytes) -> dict[str, Any]:
    """``payload`` is the TIFF header onwards (APP1 payload minus 'Exif\\0\\0')."""
    out: dict[str, Any] = {"ok": False, "ifd0": {}, "exif": {}, "ifd1": {}, "problems": [],
                           "tiff_length": len(payload)}
    if len(payload) < 8 or payload[:2] not in (b"II", b"MM"):
        out["problems"].append("no TIFF header")
        return out
    endian = "<" if payload[:2] == b"II" else ">"
    magic, ifd0_off = struct.unpack(endian + "HI", payload[2:8])
    if magic != 42:
        out["problems"].append("bad TIFF magic")
        return out
    out["endian"] = "II" if endian == "<" else "MM"
    ifd0, nxt, p = _read_ifd(payload, ifd0_off, endian)
    out["ifd0"] = ifd0
    out["problems"] += p
    if isinstance(ifd0.get("ExifIFDPointer"), int):
        ex, _, p2 = _read_ifd(payload, ifd0["ExifIFDPointer"], endian)
        out["exif"] = ex
        out["problems"] += p2
    if nxt:
        ifd1, _, p3 = _read_ifd(payload, nxt, endian)
        out["ifd1"] = ifd1
        out["problems"] += p3
    out["ok"] = True
    return out


def parse_jpeg(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"format": "jpeg", "app_segments": [], "app_segment_order": [],
                           "dqt_tables": [], "exif": None, "exif_raw_offset": None,
                           "thumbnail": {"present": False}, "makernote": {"present": False},
                           "progressive": False, "problems": []}
    pos = 2
    n = len(data)
    while pos + 4 <= n:
        if data[pos] != 0xFF:
            out["problems"].append(f"marker expected at {pos}")
            break
        marker = data[pos + 1]
        if marker == 0xD8 or 0xD0 <= marker <= 0xD7 or marker == 0xFF:
            pos += 1 if marker == 0xFF else 2
            continue
        if marker == 0xD9:
            break
        (seglen,) = struct.unpack(">H", data[pos + 2:pos + 4])
        seg = data[pos + 4:pos + 2 + seglen]
        if 0xE0 <= marker <= 0xEF:
            ident = seg.split(b"\x00", 1)[0][:16].decode("latin-1", "replace")
            name = f"APP{marker - 0xE0}"
            out["app_segments"].append({"marker": name, "identifier": ident, "offset": pos, "length": seglen})
            out["app_segment_order"].append(f"{name}:{ident}")
            if name == "APP1" and seg.startswith(b"Exif\x00\x00") and out["exif"] is None:
                tiff = seg[6:]
                out["exif_raw_offset"] = pos + 4 + 6
                out["exif"] = parse_exif(tiff)
                mn = out["exif"]["exif"].get("MakerNote")
                if isinstance(mn, dict):
                    out["makernote"] = {"present": True, "offset": mn["offset"],
                                        "length": mn["undefined_len"], "in_bounds": mn["in_bounds"]}
                ifd1 = out["exif"]["ifd1"]
                toff, tlen = ifd1.get("JPEGInterchangeFormat"), ifd1.get("JPEGInterchangeFormatLength")
                if isinstance(toff, int) and isinstance(tlen, int):
                    tb = tiff[toff:toff + tlen]
                    out["thumbnail"] = {"present": True, "offset": toff, "length": tlen,
                                        "in_bounds": toff + tlen <= len(tiff),
                                        "valid_jpeg": tb[:2] == b"\xff\xd8", "bytes": tb}
        elif marker == 0xDB:
            i = 0
            while i < len(seg):
                pq = seg[i] >> 4
                tq = seg[i] & 0x0F
                size = 64 * (2 if pq else 1)
                out["dqt_tables"].append({"id": tq, "precision": pq,
                                          "sha1": hashlib.sha1(seg[i + 1:i + 1 + size]).hexdigest()[:12]})
                i += 1 + size
        elif marker in (0xC0, 0xC1, 0xC2):
            out["progressive"] = marker == 0xC2
            prec, h, w, ncomp = struct.unpack(">BHHB", seg[:6])
            comps = []
            for c in range(ncomp):
                cid, hv, tq = struct.unpack(">BBB", seg[6 + 3 * c:9 + 3 * c])
                comps.append((cid, hv >> 4, hv & 0x0F, tq))
            out["width"], out["height"], out["components"] = w, h, ncomp
            if comps:
                out["subsampling"] = f"{comps[0][1]}x{comps[0][2]}"
        elif marker == 0xDA:
            break
        pos += 2 + seglen
    out["dqt_hash"] = hashlib.sha1("|".join(t["sha1"] for t in out["dqt_tables"]).encode()).hexdigest()[:12]
    return out


def parse_png(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"format": "png", "chunks": [], "chunk_order": [], "text_chunks": {},
                           "exif": None, "time": None, "problems": []}
    pos = 8
    n = len(data)
    while pos + 8 <= n:
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8].decode("latin-1", "replace")
        body = data[pos + 8:pos + 8 + length]
        crc_ok = None
        if pos + 12 + length <= n:
            (crc,) = struct.unpack(">I", data[pos + 8 + length:pos + 12 + length])
            crc_ok = (zlib.crc32(data[pos + 4:pos + 8 + length]) & 0xFFFFFFFF) == crc
        out["chunks"].append({"type": ctype, "length": length, "offset": pos, "crc_ok": crc_ok})
        out["chunk_order"].append(ctype)
        if ctype == "IHDR" and length >= 13:
            w, h, bd, ct = struct.unpack(">IIBB", body[:10])
            out.update({"width": w, "height": h, "bit_depth": bd, "color_type": ct})
        elif ctype == "tEXt":
            k, _, v = body.partition(b"\x00")
            out["text_chunks"][k.decode("latin-1", "replace")] = v.decode("latin-1", "replace")
        elif ctype == "iTXt":
            k, _, rest = body.partition(b"\x00")
            comp = rest[0:1] == b"\x01"
            rest = rest[2:]
            _, _, rest = rest.partition(b"\x00")
            _, _, txt = rest.partition(b"\x00")
            if comp:
                try:
                    txt = zlib.decompress(txt)
                except zlib.error:
                    txt = b""
            out["text_chunks"][k.decode("latin-1", "replace")] = txt.decode("utf-8", "replace")
        elif ctype == "zTXt":
            k, _, rest = body.partition(b"\x00")
            try:
                out["text_chunks"][k.decode("latin-1", "replace")] = zlib.decompress(rest[1:]).decode("latin-1", "replace")
            except zlib.error:
                pass
        elif ctype == "tIME" and length >= 7:
            y, mo, d, h, mi, s = struct.unpack(">HBBBBB", body[:7])
            out["time"] = f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}Z"
        elif ctype == "eXIf":
            out["exif"] = parse_exif(body)
        if crc_ok is False:
            out["problems"].append(f"{ctype} chunk CRC mismatch at {pos}")
        pos += 12 + length
        if ctype == "IEND":
            break
    return out


def _pixels(data: bytes) -> Any | None:
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        img.load()
        return img
    except Exception:
        return None


def thumbnail_similarity(main_img: Any, thumb_bytes: bytes) -> dict[str, Any] | None:
    """Mean absolute grey difference between the embedded thumbnail and the
    image downscaled to the same size (0 = identical, 255 = opposite)."""
    try:
        from PIL import Image
        thumb = Image.open(io.BytesIO(thumb_bytes)).convert("L")
        w, h = thumb.size
        ref = main_img.convert("L").resize((w, h))
        a, b = thumb.tobytes(), ref.tobytes()
        diff = sum(abs(x - y) for x, y in zip(a, b)) / max(1, len(a))
        return {"thumb_size": [w, h], "main_size": list(main_img.size), "mean_abs_diff": round(diff, 2),
                "aspect_thumb": round(w / h, 3), "aspect_main": round(main_img.size[0] / main_img.size[1], 3)}
    except Exception:
        return None


def parse(data: bytes, detected_format: str) -> dict[str, Any]:
    out = parse_jpeg(data) if detected_format == "jpeg" else parse_png(data)
    img = _pixels(data)
    out["decodable"] = img is not None
    if img is not None:
        out["pixel_size"] = list(img.size)
        out["mode"] = img.mode
        th = out.get("thumbnail", {})
        if th.get("present") and th.get("valid_jpeg"):
            out["thumbnail"]["similarity"] = thumbnail_similarity(img, th["bytes"])
    if "thumbnail" in out:
        out["thumbnail"].pop("bytes", None)
    out["app_segments_meta"] = [s for s in out.get("app_segments", []) if s["identifier"] not in ("JFIF",)]
    exif = out.get("exif")
    out["has_exif"] = bool(exif and exif.get("ok"))
    return out
