"""OCR (optical character recognition) behind a small, replaceable interface.

The rest of the application only uses ``OcrEngine`` / ``OcrResult``. The Tesseract
implementation runs the ``tesseract`` program as a subprocess:

* the image is sent on standard input and text comes back on standard output, so
  NO temporary files are created and nothing is written to disk;
* it has a timeout, runs single-threaded and at most N at a time (resource-exhaustion guard);
* errors never contain OCR text or Tesseract's own output (privacy).

If Tesseract is not installed, ``OcrUnavailableError`` is raised and the API answers 503.
Results are never faked.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import threading
from dataclasses import dataclass
from typing import Protocol

from PIL import Image, ImageOps, ImageStat

MAX_OCR_SIDE = 4000  # after upscaling
UPSCALE_BELOW = 1200  # images smaller than this (longest side) are enlarged 2x
DARK_MODE_MEAN = 110  # average brightness below this -> invert (dark-mode screenshots)
_QUALITY_BANDS = ((80.0, "good"), (60.0, "fair"))


class OcrError(Exception):
    """OCR could not be completed (timeout, engine error, too busy)."""


class OcrUnavailableError(OcrError):
    """The OCR engine is not installed or cannot be started."""


class OcrBusyError(OcrError):
    """Too many OCR jobs are already running."""


@dataclass(frozen=True)
class OcrResult:
    text: str
    mean_confidence: float | None  # 0..100, None when no words were found
    word_count: int
    engine: str

    @property
    def quality(self) -> str:
        """good / fair / poor / none: how readable the image was for OCR."""
        if self.mean_confidence is None or not self.word_count:
            return "none"
        for threshold, label in _QUALITY_BANDS:
            if self.mean_confidence >= threshold:
                return label
        return "poor"


class OcrEngine(Protocol):
    name: str

    def available(self) -> bool: ...

    def extract(self, image: Image.Image) -> OcrResult: ...


def prepare_for_ocr(image: Image.Image) -> Image.Image:
    """Grayscale, dark-mode inversion, gentle upscaling and contrast stretch."""
    if image.mode in ("RGBA", "LA", "P"):
        rgba = image.convert("RGBA")
        background = Image.new("RGBA", rgba.size, "white")
        image = Image.alpha_composite(background, rgba)
    gray = image.convert("L")
    if ImageStat.Stat(gray).mean[0] < DARK_MODE_MEAN:
        gray = ImageOps.invert(gray)
    longest = max(gray.size)
    if longest < UPSCALE_BELOW:
        factor = min(2.0, MAX_OCR_SIDE / longest)
        gray = gray.resize(
            (int(gray.width * factor), int(gray.height * factor)), Image.Resampling.LANCZOS
        )
    elif longest > MAX_OCR_SIDE:
        gray.thumbnail((MAX_OCR_SIDE, MAX_OCR_SIDE), Image.Resampling.LANCZOS)
    return ImageOps.autocontrast(gray, cutoff=1)


def parse_tsv(tsv: str) -> tuple[str, float | None, int]:
    """Rebuild text from Tesseract's TSV output and average the word confidence.

    A line wrap on a phone screen is not the end of a sentence, and splitting there would hide
    phrases such as "share the OTP" from the message rules. So words are joined per paragraph,
    and consecutive paragraphs/blocks are joined with a space unless the previous one ends a
    sentence (. ! ? :), in which case a new line starts.
    """
    paragraphs: dict[tuple[str, str, str], list[str]] = {}
    confidences: list[float] = []
    for row in tsv.splitlines()[1:]:
        cols = row.split("\t")
        if len(cols) < 12 or cols[0] != "5":  # level 5 = word
            continue
        word = cols[11].strip()
        try:
            confidence = float(cols[10])
        except ValueError:
            continue
        if not word or confidence < 0:
            continue
        key = (cols[1], cols[2], cols[3])  # page, block, paragraph
        paragraphs.setdefault(key, []).append(word)
        confidences.append(confidence)
    text = ""
    for words in paragraphs.values():
        chunk = " ".join(words)
        if not text:
            text = chunk
        elif text[-1] in ".!?:":
            text += "\n" + chunk
        else:
            text += " " + chunk

    mean = round(sum(confidences) / len(confidences), 1) if confidences else None
    return text, mean, len(confidences)


class TesseractOcrEngine:
    name = "tesseract"

    def __init__(
        self,
        command: str = "tesseract",
        languages: str = "eng",
        timeout: float = 20.0,
        max_concurrent: int = 2,
    ) -> None:
        self.command = command
        self.languages = languages
        self.timeout = timeout
        self._slots = threading.BoundedSemaphore(max_concurrent)

    def available(self) -> bool:
        return shutil.which(self.command) is not None

    def extract(self, image: Image.Image) -> OcrResult:
        if not self.available():
            raise OcrUnavailableError("OCR engine is not installed")
        buffer = io.BytesIO()
        prepare_for_ocr(image).save(buffer, format="PNG")

        if not self._slots.acquire(timeout=self.timeout):
            raise OcrBusyError("OCR is busy")
        try:
            completed = subprocess.run(  # noqa: S603 (fixed argument list, no shell)
                [self.command, "stdin", "stdout", "-l", self.languages, "--psm", "3", "tsv"],
                input=buffer.getvalue(),
                capture_output=True,
                timeout=self.timeout,
                check=False,
                env={**os.environ, "OMP_THREAD_LIMIT": "1"},
            )
        except subprocess.TimeoutExpired as exc:
            raise OcrError("OCR timed out") from exc
        except OSError as exc:
            raise OcrUnavailableError("OCR engine could not be started") from exc
        finally:
            self._slots.release()

        if completed.returncode != 0:
            raise OcrError("OCR engine failed")  # stderr is deliberately not included
        text, confidence, words = parse_tsv(completed.stdout.decode("utf-8", errors="replace"))
        return OcrResult(text=text, mean_confidence=confidence, word_count=words, engine=self.name)
