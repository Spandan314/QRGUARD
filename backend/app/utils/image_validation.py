"""Secure validation of uploaded images (screenshots now, QR images later).

Everything happens in memory: uploads are never written to disk, so there are no temporary
files to clean up and no path-traversal risk (the uploaded filename is never used).

Checks, in order (cheap checks first, so bad input is rejected before any heavy work):
 1. size: empty or larger than the configured maximum -> reject
 2. magic bytes: the file must really start like a PNG, JPEG or WEBP (extension is ignored)
 3. header parse: Pillow must agree on the format
 4. dimensions: checked from the header BEFORE decoding pixels (decompression-bomb guard):
    at least 16x16, at most 10000 px per side and the configured number of megapixels
 5. full decode: truncated or corrupt images are rejected
"""

from __future__ import annotations

import io
import warnings
from dataclasses import dataclass

from PIL import Image, UnidentifiedImageError

from app.errors import APIError

MIN_SIDE = 16
MAX_SIDE = 10_000

# Magic numbers of the accepted formats -> Pillow format name.
_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
)
ACCEPTED_FORMATS = ("PNG", "JPEG", "WEBP")


@dataclass(frozen=True)
class ValidatedImage:
    image: Image.Image  # decoded, first frame only
    format: str  # PNG / JPEG / WEBP
    width: int
    height: int
    size_bytes: int

    def describe(self) -> dict[str, object]:
        return {
            "format": self.format,
            "width": self.width,
            "height": self.height,
            "size_bytes": self.size_bytes,
        }


def sniff_format(data: bytes) -> str | None:
    """Detect the real file type from its first bytes (never from the filename)."""
    for signature, name in _SIGNATURES:
        if data.startswith(signature):
            return name
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WEBP"
    return None


def validate_image(data: bytes, max_bytes: int, max_pixels: int) -> ValidatedImage:
    if not data:
        raise APIError(400, "EMPTY_FILE", "The uploaded file is empty.")
    if len(data) > max_bytes:
        raise APIError(
            413, "FILE_TOO_LARGE", f"Image must be {max_bytes // (1024 * 1024)} MB or smaller."
        )

    expected = sniff_format(data)
    if expected is None:
        raise APIError(
            415, "UNSUPPORTED_MEDIA_TYPE", "Only PNG, JPEG and WEBP images are supported."
        )

    try:
        with warnings.catch_warnings():
            # Treat Pillow's decompression-bomb warning as an error.
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            header = Image.open(io.BytesIO(data))
            detected = header.format
            width, height = header.size
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise APIError(413, "IMAGE_TOO_LARGE", "The image has too many pixels.") from exc
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError) as exc:
        raise APIError(422, "UNPROCESSABLE_IMAGE", "The image file is damaged or invalid.") from exc

    if detected != expected or detected not in ACCEPTED_FORMATS:
        raise APIError(
            415, "UNSUPPORTED_MEDIA_TYPE", "Only PNG, JPEG and WEBP images are supported."
        )
    if width < MIN_SIDE or height < MIN_SIDE:
        raise APIError(
            422, "IMAGE_TOO_SMALL", f"The image must be at least {MIN_SIDE}x{MIN_SIDE} pixels."
        )
    if width > MAX_SIDE or height > MAX_SIDE or width * height > max_pixels:
        raise APIError(
            413,
            "IMAGE_TOO_LARGE",
            f"The image is too large (maximum {MAX_SIDE} pixels per side and "
            f"{max_pixels // 1_000_000} megapixels).",
        )

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            # verify() checks structure/checksums; it leaves the object unusable, so re-open.
            Image.open(io.BytesIO(data)).verify()
            image = Image.open(io.BytesIO(data))
            image.seek(0)  # animated images: first frame only
            image.load()  # full decode: fails on truncated/corrupt data
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise APIError(413, "IMAGE_TOO_LARGE", "The image has too many pixels.") from exc
    except (OSError, ValueError, SyntaxError, EOFError) as exc:
        raise APIError(422, "UNPROCESSABLE_IMAGE", "The image file is damaged or invalid.") from exc

    return ValidatedImage(image, detected, width, height, len(data))
