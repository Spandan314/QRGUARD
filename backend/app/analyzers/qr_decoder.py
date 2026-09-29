"""Decode QR codes from an already-validated image (OpenCV, in memory)."""

from __future__ import annotations

import logging

import cv2
import numpy as np
from PIL import Image, ImageOps

logger = logging.getLogger("qrguard.qr")

MAX_QR_CODES = 5  # more codes than this in one image are ignored
MAX_DECODE_SIDE = 2000  # larger images are downscaled first (speed, memory)
MAX_CONTENT_CHARS = 4096  # longer payloads are not analysed


def _to_bgr(image: Image.Image) -> np.ndarray:
    rgb = image.convert("RGB")
    if max(rgb.size) > MAX_DECODE_SIDE:
        rgb = rgb.copy()
        rgb.thumbnail((MAX_DECODE_SIDE, MAX_DECODE_SIDE), Image.Resampling.LANCZOS)
    return cv2.cvtColor(np.asarray(rgb), cv2.COLOR_RGB2BGR)


def _decode(array: np.ndarray) -> list[str]:
    detector = cv2.QRCodeDetector()
    try:
        ok, texts, _, _ = detector.detectAndDecodeMulti(array)
        found = [t for t in texts if t] if ok else []
        if not found:
            text, _, _ = detector.detectAndDecode(array)
            found = [text] if text else []
    except cv2.error:
        logger.warning("QR decoder error", extra={"event": "qr_decode_error"})
        return []
    return found


def decode_qr_codes(image: Image.Image) -> list[str]:
    """Return the decoded QR payloads (unique, at most MAX_QR_CODES)."""
    found = _decode(_to_bgr(image))
    if not found:  # light-on-dark ("inverted") QR codes, e.g. in dark-mode screenshots
        found = _decode(_to_bgr(ImageOps.invert(image.convert("RGB"))))
    unique: list[str] = []
    for text in found:
        text = text.strip()
        if text and len(text) <= MAX_CONTENT_CHARS and text not in unique:
            unique.append(text)
    return unique[:MAX_QR_CODES]
