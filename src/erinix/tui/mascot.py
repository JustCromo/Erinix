"""The Erinix mascot: a pixel-art hedgehog drawn with half blocks.

Every terminal cell shows two pixels (upper/lower block), so a grid of 32x22
pixels takes 32 columns by 11 rows. The drawing is generated deterministically
(no image file). At least 256 colors are needed; otherwise the welcome screen
uses a text fallback.
"""

from __future__ import annotations

import math

from erinix.ui.render import Seg, merge
from erinix.ui.theme import Theme

WIDTH, HEIGHT = 32, 22

RGB = tuple[int, int, int]

SPINES: tuple[RGB, ...] = ((112, 76, 52), (146, 102, 70), (182, 134, 94))
SPINE_TIP: RGB = (222, 180, 134)
FACE: RGB = (236, 202, 163)
FACE_SHADE: RGB = (204, 160, 120)
BELLY: RGB = (244, 220, 190)
NOSE: RGB = (40, 26, 20)
EYE: RGB = (22, 16, 14)
SHINE: RGB = (255, 255, 255)
LEAF: RGB = (226, 122, 63)
LEAF_VEIN: RGB = (168, 78, 38)


def _in_ellipse(x: float, y: float, cx: float, cy: float, rx: float, ry: float) -> bool:
    return ((x - cx) / rx) ** 2 + ((y - cy) / ry) ** 2 <= 1.0


def _triangle(t: float) -> float:
    t %= 1.0
    return t * 2 if t < 0.5 else (1 - t) * 2


def pixels() -> list[list[RGB | None]]:
    grid: list[list[RGB | None]] = [[None] * WIDTH for _ in range(HEIGHT)]
    cx, cy, rx, ry = 17.5, 11.0, 13.6, 9.6

    # Spiny body: a dome with a jagged edge and diagonal strokes that suggest spines.
    for y in range(HEIGHT):
        for x in range(WIDTH):
            px, py = x + 0.5, y + 0.5
            dx, dy = (px - cx) / rx, (py - cy) / ry
            rho = math.hypot(dx, dy)
            theta = math.atan2(dy, dx)
            limit = 1.0
            if dy < 0.45:
                limit = 1.0 + 0.17 * _triangle(theta * 13 / math.pi)
            if rho <= limit:
                band = (2 * x + y) // 3
                color = SPINES[band % 3]
                if (x + 2 * y) % 5 == 0:
                    color = SPINES[(band + 1) % 3]
                if rho > 0.78 and band % 2 == 0:
                    color = SPINE_TIP
                grid[y][x] = color

    def paint(cond, color):
        for y in range(HEIGHT):
            for x in range(WIDTH):
                if cond(x + 0.5, y + 0.5):
                    grid[y][x] = color

    # Paws, snout and face (on top of the spines).
    paint(lambda x, y: _in_ellipse(x, y, 13.0, 20.3, 2.7, 1.7), FACE_SHADE)
    paint(lambda x, y: _in_ellipse(x, y, 23.0, 20.3, 2.7, 1.7), FACE_SHADE)
    paint(lambda x, y: _in_ellipse(x, y, 7.4, 15.6, 7.0, 5.2), FACE)
    paint(lambda x, y: _in_ellipse(x, y, 3.0, 16.6, 3.4, 2.4), FACE)
    paint(lambda x, y: _in_ellipse(x, y, 9.0, 19.0, 4.2, 1.9), BELLY)
    paint(lambda x, y: _in_ellipse(x, y, 9.5, 11.2, 2.0, 1.7), FACE_SHADE)   # ear
    for x, y in ((0, 16), (1, 16), (0, 17), (1, 17)):
        grid[y][x] = NOSE
    for x, y in ((6, 14), (7, 14), (6, 15), (7, 15)):
        grid[y][x] = EYE
    grid[14][6] = SHINE
    # Autumn leaf on the back: a touch of cold orange.
    for x, y, c in ((20, 3, LEAF), (21, 3, LEAF), (19, 4, LEAF), (20, 4, LEAF_VEIN), (21, 4, LEAF),
                    (22, 4, LEAF), (20, 5, LEAF), (21, 5, LEAF), (22, 5, LEAF), (23, 5, LEAF)):
        grid[y][x] = c
    return grid


def lines(theme: Theme) -> list[list[Seg]]:
    """Lines of colored fragments (half blocks). Empty if the terminal is not capable enough."""
    if theme.color_level < 2 or not theme.unicode:
        return []
    grid = pixels()
    out: list[list[Seg]] = []
    for y in range(0, HEIGHT, 2):
        row: list[Seg] = []
        for x in range(WIDTH):
            top, bottom = grid[y][x], grid[y + 1][x]
            if top is None and bottom is None:
                row.append(Seg(" "))
            elif bottom is None:
                row.append(Seg("▀", fg=top))
            elif top is None:
                row.append(Seg("▄", fg=bottom))
            elif top == bottom:
                row.append(Seg("█", fg=top))
            else:
                row.append(Seg("▀", fg=top, bg=bottom))
        out.append(merge(row))
    return out
