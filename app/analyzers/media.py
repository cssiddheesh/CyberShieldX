"""Media Forensics: stdlib-only image parsing (PRD section 7.7).

Reads PNG, JPEG, GIF, BMP and WebP headers/metadata by hand - no imaging
library, nothing executed. Reports file facts, metadata presence, basic
forensic indicators and a rough JPEG quality estimate from quantization
tables. Wording stays probabilistic ("possible indicators", never proof).
"""
from __future__ import annotations

import struct
import zlib
from typing import Any

from app.models.evidence import Evidence, IndicatorType, ResultOrigin

SOURCE = "Media Forensics"
SOURCE_TYPE = "local_media_analysis"

MAX_IMAGE_BYTES = 25 * 1024 * 1024

# Standard IJG luminance quantization table (quality 50) for JPEG estimation.
_STD_LUMA = (
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
)


def _ascii_strings(blob: bytes, min_len: int = 4) -> list[str]:
    found, current = [], bytearray()
    for byte in blob:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= min_len:
                found.append(bytes(current).decode("ascii"))
            current = bytearray()
    if len(current) >= min_len:
        found.append(bytes(current).decode("ascii"))
    return found


def _parse_png(data: bytes) -> dict[str, Any]:
    facts: dict[str, Any] = {"format": "PNG"}
    if len(data) < 33:
        raise ValueError("Truncated PNG.")
    width, height, depth, color = struct.unpack(">IIBB", data[16:26])
    facts.update({"width": width, "height": height, "bit_depth": depth,
                  "color_type": color})
    texts, software, created = [], [], []
    pos = 8
    try:
        while pos + 8 <= len(data):
            length = struct.unpack(">I", data[pos:pos + 4])[0]
            ctype = data[pos + 4:pos + 8].decode("ascii", errors="replace")
            chunk = data[pos + 8:pos + 8 + length]
            if ctype in ("tEXt", "zTXt", "iTXt"):
                keyword = chunk.split(b"\x00", 1)[0][:60].decode("ascii", errors="replace")
                texts.append(keyword)
                low = keyword.lower()
                if any(k in low for k in ("software", "creator", "producer", "photoshop", "gimp")):
                    software.append(keyword)
                if "creation" in low or "date" in low:
                    created.append(keyword)
            elif ctype == "eXIf":
                texts.append("EXIF profile")
            if ctype == "IEND":
                break
            pos += 12 + length
    except (struct.error, IndexError, UnicodeDecodeError):
        facts["parse_note"] = "Chunk walk stopped early (unusual structure)."
    facts["text_chunks"] = texts
    facts["software_tags"] = software
    facts["has_metadata"] = bool(texts)
    return facts


def _parse_jpeg(data: bytes) -> dict[str, Any]:
    facts: dict[str, Any] = {"format": "JPEG"}
    app_segments: list[str] = []
    comments: list[str] = []
    dqt_tables: list[list[int]] = []
    width = height = 0
    pos = 2
    try:
        while pos + 4 <= len(data):
            if data[pos] != 0xFF:
                break
            marker = data[pos + 1]
            if marker in (0xD8, 0xD9) or (0xD0 <= marker <= 0xD7):
                pos += 2
                continue
            if pos + 4 > len(data):
                break
            seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            seg = data[pos + 4:pos + 2 + seg_len]
            if marker == 0xE1 and seg[:6] in (b"Exif\x00\x00",):
                app_segments.append("EXIF")
                for s in _ascii_strings(seg):
                    if any(k in s for k in ("Canon", "NIKON", "SONY", "Adobe", "Photoshop",
                                            "Lightroom", "GIMP", "paint.net", "Camera")):
                        app_segments.append(f"tag:{s[:60]}")
            elif marker == 0xE0 and seg[:5] == b"JFIF\x00":
                app_segments.append("JFIF")
            elif marker == 0xEE and seg[:7] == b"Adobe\x00":
                app_segments.append("Adobe")
            elif marker == 0xED:
                for s in _ascii_strings(seg):
                    if "Photoshop" in s or "Adobe" in s:
                        app_segments.append("Photoshop IRB")
                        break
            elif marker == 0xFE:
                comments.append(seg.decode("utf-8", errors="replace")[:120])
            elif marker == 0xDB:  # DQT: one or more 65-byte 8-bit tables
                off = 0
                while off + 65 <= len(seg):
                    info, table = seg[off], seg[off + 1:off + 65]
                    if info & 0xF0 == 0:  # 8-bit entries only
                        dqt_tables.append(list(table))
                    off += 65
            elif marker in (0xC0, 0xC1, 0xC2):  # SOF: precision(1) height(2) width(2)
                if len(seg) >= 5:
                    height, width = struct.unpack(">HH", seg[1:5])
            elif marker == 0xDA:  # SOS: image data follows
                break
            pos += 2 + seg_len
    except (struct.error, IndexError):
        facts["parse_note"] = "Segment walk stopped early (unusual structure)."
    facts.update({"width": width, "height": height, "segments": sorted(set(app_segments)),
                  "comments": comments, "has_metadata": bool(app_segments or comments)})
    if dqt_tables:
        facts["jpeg_quality_estimate"] = _estimate_jpeg_quality(dqt_tables[0])
    return facts


def _estimate_jpeg_quality(table: list[int]) -> int:
    """Compare a DQT against the standard table to guess IJG quality 1-100."""
    best_q, best_err = 50, float("inf")
    for quality in range(5, 101, 5):
        scale = 5000 / quality if quality < 50 else 200 - quality * 2
        err = sum(abs(t - min(255, max(1, (s * scale + 50) // 100)))
                  for t, s in zip(table, _STD_LUMA))
        if err < best_err:
            best_q, best_err = quality, err
    return best_q


def _parse_gif(data: bytes) -> dict[str, Any]:
    if len(data) < 10:
        raise ValueError("Truncated GIF.")
    width, height = struct.unpack("<HH", data[6:10])
    return {"format": "GIF", "width": width, "height": height,
            "has_metadata": False, "segments": []}


def _parse_bmp(data: bytes) -> dict[str, Any]:
    if len(data) < 26:
        raise ValueError("Truncated BMP.")
    width, height = struct.unpack("<ii", data[18:26])
    return {"format": "BMP", "width": abs(width), "height": abs(height),
            "has_metadata": False, "segments": []}


def _parse_webp(data: bytes) -> dict[str, Any]:
    facts: dict[str, Any] = {"format": "WebP", "has_metadata": False, "segments": []}
    if len(data) < 30:
        raise ValueError("Truncated WebP.")
    fourcc = data[12:16]
    facts["variant"] = fourcc.decode("ascii", errors="replace")
    if fourcc == b"VP8 " and len(data) >= 30:
        width = struct.unpack("<H", data[26:28])[0] & 0x3FFF
        height = struct.unpack("<H", data[28:30])[0] & 0x3FFF
        facts.update({"width": width, "height": height})
    elif fourcc == b"VP8L" and len(data) >= 25:
        bits = struct.unpack("<I", data[21:25])[0]
        facts.update({"width": (bits & 0x3FFF) + 1, "height": ((bits >> 14) & 0x3FFF) + 1})
    if b"EXIF" in data[:64] or b"XMP" in data[:256]:
        facts["has_metadata"] = True
        facts["segments"] = ["EXIF/XMP chunk"]
    return facts


def identify_image(data: bytes) -> str | None:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if data[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF"
    if data[:2] == b"BM":
        return "BMP"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WebP"
    return None


def analyze_image(data: bytes, filename: str) -> dict[str, Any]:
    """Static image forensics. Returns a JSON-serializable dict (no pixel data)."""
    data = data if isinstance(data, bytes) else b""
    name = (filename or "image").strip()[:255] or "image"
    kind = identify_image(data)
    indicators: list[dict[str, Any]] = []

    def add(id_: str, title: str, detail: str, severity: str, weight: int, confidence: float):
        indicators.append({"id": id_, "title": title, "detail": detail,
                           "severity": severity, "weight": weight, "confidence": confidence})

    if kind is None:
        raise ValueError("Not a recognised image (PNG, JPEG, GIF, BMP or WebP).")

    parsers = {"PNG": _parse_png, "JPEG": _parse_jpeg, "GIF": _parse_gif,
               "BMP": _parse_bmp, "WebP": _parse_webp}
    try:
        facts = parsers[kind](data)
    except ValueError as exc:
        raise ValueError(f"The file claims to be {kind} but is damaged: {exc}")
    facts["filename"] = name
    facts["size_bytes"] = len(data)

    width, height = facts.get("width") or 0, facts.get("height") or 0
    if width and height:
        facts["megapixels"] = round(width * height / 1_000_000, 2)

    if not facts.get("has_metadata"):
        add("stripped_metadata", "No embedded metadata found",
            "Cameras normally embed EXIF data. Stripped metadata is routine for social-media "
            "uploads - and also for AI-generated images, which carry no camera history. "
            "Possible indicator only, never proof.", "low", 6, 0.4)
    else:
        software_tags = [t for t in facts.get("software_tags", []) if t]
        tagged = [s[4:] for s in facts.get("segments", []) if s.startswith("tag:")]
        seen = software_tags + tagged
        if seen:
            add("editor_tag", f"Software tag present: {seen[0][:60]}",
                "The file names the software that wrote it. Normal for edited photos; "
                "relevant when authenticity matters.", "low", 5, 0.7)
    if kind == "JPEG" and facts.get("jpeg_quality_estimate") is not None:
        q = facts["jpeg_quality_estimate"]
        facts["compression"] = f"estimated IJG quality ~{q}"
        if q <= 60:
            add("heavy_compression", f"Heavy recompression (quality ~{q})",
                "Repeated re-saving degrades detail and can hide splice boundaries. "
                "Also normal for images passed around messaging apps.", "low", 5, 0.45)
    if width and height and (width < 64 or height < 64):
        add("tiny_image", f"Very small image ({width}x{height})",
            "Thumbnail-sized images carry too little detail for meaningful forensics.", "info", 0, 0.8)
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError("Image exceeds the size limit.")

    evidence = [Evidence(
        f"{name} ({kind} {width}x{height})", IndicatorType.IMAGE, SOURCE, SOURCE_TYPE,
        item["title"], item["severity"], item["confidence"],  # type: ignore[arg-type]
        item["detail"] + " Possible AI-generated/manipulated indicators are probabilistic only.",
        "", "detected" if item["weight"] else "informational", ResultOrigin.LOCAL)
        for item in indicators]
    if not indicators:
        evidence.append(Evidence(
            f"{name} ({kind} {width}x{height})", IndicatorType.IMAGE, SOURCE, SOURCE_TYPE,
            "No forensic anomalies in metadata or structure", "info", 0.6,
            "Headers, dimensions and metadata look ordinary. File-level forensics cannot detect "
            "skilful manipulation or AI generation - treat as one weak signal.",
            "", "informational", ResultOrigin.LOCAL))

    return {"facts": facts, "indicators": indicators,
            "evidence": [e.to_dict() for e in evidence],
            "local_weights": [{"id": i["id"], "weight": i["weight"], "severity": i["severity"]}
                              for i in indicators]}
