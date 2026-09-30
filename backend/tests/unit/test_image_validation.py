import pytest
from PIL import Image

from app.errors import APIError
from app.utils.image_validation import sniff_format, validate_image
from tests.images import blank, encode, png_with_declared_size

MB = 1024 * 1024
MAX_PIXELS = 25_000_000


def check(data: bytes, max_bytes: int = 5 * MB, max_pixels: int = MAX_PIXELS):
    return validate_image(data, max_bytes, max_pixels)


def assert_rejected(data: bytes, status: int, code: str, **kwargs):
    with pytest.raises(APIError) as err:
        check(data, **kwargs)
    assert (err.value.status, err.value.code) == (status, code)
    return err.value


@pytest.mark.parametrize("fmt", ["PNG", "JPEG", "WEBP"])
def test_supported_formats_are_accepted(fmt):
    result = check(blank(320, 200, fmt=fmt))
    assert result.format == fmt
    assert result.describe()["width"] == 320 and result.describe()["height"] == 200
    assert result.image.size == (320, 200)


def test_format_is_detected_from_content_not_name():
    assert sniff_format(blank(fmt="JPEG")) == "JPEG"
    assert sniff_format(b"GIF89a....") is None


def test_empty_file():
    assert_rejected(b"", 400, "EMPTY_FILE")


def test_file_too_large():
    assert_rejected(blank(), 413, "FILE_TOO_LARGE", max_bytes=100)


@pytest.mark.parametrize(
    "data",
    [
        encode(Image.new("RGB", (50, 50)), "GIF"),
        encode(Image.new("RGB", (50, 50)), "BMP"),
        b"%PDF-1.7\n...",
        b"MZ\x90\x00 fake windows executable",
        b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>",
        b"#!/bin/sh\nrm -rf /\n",
    ],
)
def test_unsupported_types_are_rejected(data):
    assert_rejected(data, 415, "UNSUPPORTED_MEDIA_TYPE")


def test_png_signature_with_other_content_is_rejected():
    assert_rejected(b"\x89PNG\r\n\x1a\n" + blank(fmt="JPEG"), 422, "UNPROCESSABLE_IMAGE")


def test_truncated_images_are_rejected():
    for fmt in ("PNG", "JPEG"):
        data = blank(600, 400, fmt=fmt, color="red")
        with pytest.raises(APIError) as err:
            check(data[: len(data) // 2])
        assert err.value.code == "UNPROCESSABLE_IMAGE"


def test_corrupt_png_is_rejected():
    data = bytearray(blank())
    data[40:60] = b"\x00" * 20
    assert_rejected(bytes(data), 422, "UNPROCESSABLE_IMAGE")


def test_too_small():
    assert_rejected(blank(8, 8), 422, "IMAGE_TOO_SMALL")


def test_too_many_pixels_is_rejected_before_decoding():
    # 6000 x 5000 = 30 MP of plain white compresses to a small file.
    assert_rejected(blank(6000, 5000), 413, "IMAGE_TOO_LARGE")
    assert_rejected(blank(11000, 20), 413, "IMAGE_TOO_LARGE")  # longer than 10000 px


def test_decompression_bomb_header_is_rejected():
    error = assert_rejected(png_with_declared_size(60000, 60000), 413, "IMAGE_TOO_LARGE")
    assert "pixels" in error.message


def test_error_messages_do_not_expose_paths_or_internals():
    for data in (b"", b"MZ...", blank(8, 8), png_with_declared_size(60000, 60000)):
        with pytest.raises(APIError) as err:
            check(data)
        assert "/" not in err.value.message.replace("/api", "")
        assert "Traceback" not in err.value.message
