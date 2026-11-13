import struct
import xml.etree.ElementTree as ET
import zlib

import pytest

from erinix import assets


def chunks(png):
    pos, out = 8, {}
    while pos < len(png):
        length, kind = struct.unpack(">I4s", png[pos:pos + 8])
        out.setdefault(kind, png[pos + 8:pos + 8 + length])
        assert zlib.crc32(png[pos + 4:pos + 8 + length]) == struct.unpack(">I", png[pos + 8 + length:pos + 12 + length])[0]
        pos += 12 + length
    return out


def test_svg_is_valid_self_contained_and_deterministic():
    svg = assets.logo_svg()
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg") and root.attrib["viewBox"] == "0 0 32 32"
    assert "http" not in svg.replace("http://www.w3.org/2000/svg", "") and "<script" not in svg and "href" not in svg
    assert len(root.findall("{http://www.w3.org/2000/svg}rect")) > 100 and svg == assets.logo_svg()


def test_hedgehog_without_background_is_cropped_and_transparent():
    svg = assets.hedgehog_svg()
    root = ET.fromstring(svg)
    assert root.attrib["viewBox"] == "0 5 32 22" and "rx=" not in svg and "#1f1b24" not in svg and "<script" not in svg
    assert assets.logo_svg(background=False) == svg and assets.logo_svg() != svg


@pytest.mark.parametrize("size", [32, 64, 256])
def test_png_is_valid(size):
    png = assets.logo_png(size)
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    c = chunks(png)
    assert struct.unpack(">IIBBBBB", c[b"IHDR"]) == (size, size, 8, 6, 0, 0, 0)
    raw = zlib.decompress(c[b"IDAT"])
    assert len(raw) == size * (1 + size * 4) and c[b"IEND"] == b""
    assert raw[1:5] == b"\x00\x00\x00\x00"                          # rounded corner is transparent
    middle = raw[(size // 2) * (1 + size * 4) + 1 + (size // 2) * 4:][:4]
    assert middle[3] == 255                                          # the picture itself is opaque


@pytest.mark.parametrize("bad", [0, 31, 100, 2048, -32])
def test_png_rejects_odd_sizes(bad):
    with pytest.raises(ValueError):
        assets.logo_png(bad)
