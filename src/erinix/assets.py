"""The Erinix logo as SVG and PNG, drawn from the same pixel art as the console mascot.

No image files and no dependencies: both formats are generated from the mascot grid.
"""

from __future__ import annotations

import struct
import zlib

from erinix.tui import mascot

GRID = 32
BACKGROUND = (31, 27, 36)
RADIUS = 6                       # corner radius, in logo pixels
_Y_OFFSET = (GRID - mascot.HEIGHT) // 2


def _hex(color: tuple[int, int, int]) -> str:
    return "#{:02x}{:02x}{:02x}".format(*color)


def logo_svg() -> str:
    grid = mascot.pixels()
    rects = []
    for y, row in enumerate(grid):
        x = 0
        while x < mascot.WIDTH:
            color = row[x]
            if color is None:
                x += 1
                continue
            end = x
            while end < mascot.WIDTH and row[end] == color:
                end += 1
            rects.append(f'<rect x="{x}" y="{y + _Y_OFFSET}" width="{end - x}" height="1" fill="{_hex(color)}"/>')
            x = end
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="256" height="256" '
            'shape-rendering="crispEdges" role="img" aria-label="Erinix">'
            f'<rect width="32" height="32" rx="{RADIUS}" fill="{_hex(BACKGROUND)}"/>' + "".join(rects) + "</svg>")


def _chunk(kind: bytes, data: bytes) -> bytes:
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def logo_png(size: int = 256) -> bytes:
    """A square RGBA PNG (rounded corners are transparent). `size` must be a multiple of 32."""
    if size % GRID or not 32 <= size <= 1024:
        raise ValueError("size must be a multiple of 32 between 32 and 1024")
    scale = size // GRID
    grid = mascot.pixels()
    radius = RADIUS * scale
    rows = bytearray()
    for y in range(size):
        rows.append(0)                                           # filter type: none
        gy = y // scale - _Y_OFFSET
        for x in range(size):
            dx = max(radius - x, x - (size - 1 - radius), 0)
            dy = max(radius - y, y - (size - 1 - radius), 0)
            if dx * dx + dy * dy > radius * radius:
                rows += b"\x00\x00\x00\x00"                      # outside the rounded corner
                continue
            color = grid[gy][x // scale] if 0 <= gy < mascot.HEIGHT else None
            r, g, b = color or BACKGROUND
            rows += bytes((r, g, b, 255))
    return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + _chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + _chunk(b"IEND", b""))
