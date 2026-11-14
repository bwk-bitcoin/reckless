#!/usr/bin/env python3
"""Packs the app mark's PNG renders into the platform icon files.

    pack_icons.py <png dir> <png prefix> <out dir>

Reads <png dir>/<png prefix><size>.png and writes:
  <out dir>/reckless.ico   Windows: 16, 24, 32, 48, 64, 256 px, each a PNG entry
  <out dir>/reckless.icns  macOS: 16 to 512 px at @1x and @2x (1024 px for 512@2x)
Called by generate_mark.sh, which renders the PNGs with Qt's SVG renderer.
"""

import struct
import sys
from pathlib import Path

ICO_SIZES = [16, 24, 32, 48, 64, 256]
# (OSType, pixel size): 16, 32, 64, 128, 256 and 512 px, then the @2x sizes of
# 16, 32, 128, 256 and 512 pt.
ICNS_TYPES = [
    (b"icp4", 16),
    (b"icp5", 32),
    (b"icp6", 64),
    (b"ic07", 128),
    (b"ic08", 256),
    (b"ic09", 512),
    (b"ic11", 32),  # 16@2x
    (b"ic12", 64),  # 32@2x
    (b"ic13", 256),  # 128@2x
    (b"ic14", 512),  # 256@2x
    (b"ic10", 1024),  # 512@2x
]
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def png(png_dir: Path, prefix: str, size: int) -> bytes:
    data = (png_dir / f"{prefix}{size}.png").read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        raise SystemExit(f"pack_icons: {prefix}{size}.png is not a PNG")
    width, height = struct.unpack(">II", data[16:24])
    if (width, height) != (size, size):
        raise SystemExit(f"pack_icons: {prefix}{size}.png is {width}x{height}, not {size}x{size}")
    return data


def ico(images: list[tuple[int, bytes]]) -> bytes:
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = len(header) + 16 * len(images)
    entries = b""
    blobs = b""
    for size, data in images:
        side = 0 if size >= 256 else size  # 0 means 256 in an ICONDIRENTRY
        entries += struct.pack("<BBBBHHII", side, side, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    return header + entries + blobs


def icns(images: list[tuple[bytes, bytes]]) -> bytes:
    body = b"".join(kind + struct.pack(">I", 8 + len(data)) + data for kind, data in images)
    return b"icns" + struct.pack(">I", 8 + len(body)) + body


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    png_dir, prefix, out_dir = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    (out_dir / "reckless.ico").write_bytes(
        ico([(size, png(png_dir, prefix, size)) for size in ICO_SIZES])
    )
    (out_dir / "reckless.icns").write_bytes(
        icns([(kind, png(png_dir, prefix, size)) for kind, size in ICNS_TYPES])
    )


if __name__ == "__main__":
    main()
