"""Synthetic test images (DEMO / TEST DATA), generated in memory at test time."""

from __future__ import annotations

import io
import struct
import zlib

from PIL import Image, ImageDraw, ImageFont


def render_text(
    lines: list[str], *, dark: bool = False, size: int = 26, width: int = 1000, fmt: str = "PNG"
) -> bytes:
    """A 'screenshot' with the given text lines."""
    font = ImageFont.load_default(size=size)
    image = Image.new("RGB", (width, 60 + 50 * len(lines)), "#111111" if dark else "white")
    draw = ImageDraw.Draw(image)
    for i, line in enumerate(lines):
        draw.text((20, 30 + 50 * i), line, fill="#eeeeee" if dark else "black", font=font)
    return encode(image, fmt)


def blank(width: int = 400, height: int = 300, fmt: str = "PNG", color: str = "white") -> bytes:
    return encode(Image.new("RGB", (width, height), color), fmt)


def encode(image: Image.Image, fmt: str = "PNG") -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, format=fmt)
    return buffer.getvalue()


def png_with_declared_size(width: int, height: int) -> bytes:
    """A tiny, valid-looking PNG whose header claims a huge size (decompression-bomb shape)."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)  # 8-bit grayscale
    idat = zlib.compress(b"\x00" * 16)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def qr_image(data: str, size: int = 300, invert: bool = False) -> Image.Image:
    """A QR code as a PIL image (DEMO / TEST DATA)."""
    import qrcode

    image = qrcode.make(data).convert("RGB").resize((size, size), Image.Resampling.NEAREST)
    if invert:
        from PIL import ImageOps

        image = ImageOps.invert(image)
    return image


def qr_png(*codes: str, size: int = 300, invert: bool = False, gap: int = 40) -> bytes:
    """One or more QR codes side by side on a canvas, encoded as PNG."""
    background = "black" if invert else "white"
    canvas = Image.new("RGB", (gap + len(codes) * (size + gap), size + 2 * gap), background)
    for i, code in enumerate(codes):
        canvas.paste(qr_image(code, size, invert), (gap + i * (size + gap), gap))
    return encode(canvas)
