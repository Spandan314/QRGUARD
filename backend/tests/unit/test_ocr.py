import shutil
import subprocess

import pytest
from PIL import Image, ImageStat

from app.analyzers import ocr
from app.analyzers.ocr import (
    OcrBusyError,
    OcrError,
    OcrResult,
    OcrUnavailableError,
    TesseractOcrEngine,
    parse_tsv,
    prepare_for_ocr,
)
from tests.images import render_text

HAS_TESSERACT = shutil.which("tesseract") is not None
HEADER = (
    "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext"
)


def row(level, block, par, line, conf, text):
    return f"{level}\t1\t{block}\t{par}\t{line}\t1\t0\t0\t10\t10\t{conf}\t{text}"


def test_parse_tsv_joins_words_per_paragraph_and_averages_confidence():
    tsv = "\n".join(
        [
            HEADER,
            row(1, 0, 0, 0, -1, ""),  # page row
            row(5, 1, 1, 1, 90, "Share"),
            row(5, 1, 1, 2, 80, "the"),  # wrapped line, same paragraph
            row(5, 1, 1, 2, 70, "OTP"),
            row(5, 1, 2, 1, 100, "Thanks"),
            row(5, 1, 2, 1, -1, "ignored"),
            row(5, 1, 2, 1, 50, "  "),
        ]
    )
    text, confidence, words = parse_tsv(tsv)
    assert text == "Share the OTP Thanks"  # no sentence punctuation -> joined
    assert confidence == 85.0 and words == 4


def test_parse_tsv_starts_a_new_line_after_a_sentence_end():
    tsv = "\n".join(
        [
            HEADER,
            row(5, 1, 1, 1, 90, "Please"),
            row(5, 1, 1, 1, 90, "share"),  # block 1 ends without punctuation
            row(5, 2, 1, 1, 90, "OTP."),  # block 2 continues the sentence, then ends it
            row(5, 3, 1, 1, 90, "Thanks!"),
        ]
    )
    assert parse_tsv(tsv)[0] == "Please share OTP.\nThanks!"


def test_parse_tsv_empty():
    assert parse_tsv(HEADER) == ("", None, 0)
    assert parse_tsv("") == ("", None, 0)


@pytest.mark.parametrize(
    ("confidence", "words", "quality"),
    [(95, 3, "good"), (80, 3, "good"), (65, 3, "fair"), (40, 3, "poor"), (None, 0, "none")],
)
def test_quality_bands(confidence, words, quality):
    assert OcrResult("x", confidence, words, "t").quality == quality


def test_prepare_inverts_dark_mode_and_upscales_small_images():
    dark = Image.new("RGB", (300, 100), "#101010")
    prepared = prepare_for_ocr(dark)
    assert prepared.mode == "L" and prepared.size == (600, 200)
    assert ImageStat.Stat(prepared).mean[0] > 200


def test_prepare_handles_transparency_and_huge_images():
    assert prepare_for_ocr(Image.new("RGBA", (200, 100), (0, 0, 0, 0))).mode == "L"
    assert max(prepare_for_ocr(Image.new("RGB", (6000, 3000), "white")).size) == 4000


def test_missing_engine_is_reported_not_faked():
    engine = TesseractOcrEngine(command="definitely-not-installed-tesseract")
    assert engine.available() is False
    with pytest.raises(OcrUnavailableError):
        engine.extract(Image.new("RGB", (100, 100), "white"))


def _engine_with(monkeypatch, fake_run):
    monkeypatch.setattr(ocr.shutil, "which", lambda cmd: "/usr/bin/tesseract")
    monkeypatch.setattr(ocr.subprocess, "run", fake_run)
    return TesseractOcrEngine(timeout=1)


def test_timeout_becomes_ocr_error(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired("tesseract", 1)

    with pytest.raises(OcrError, match="timed out"):
        _engine_with(monkeypatch, fake_run).extract(Image.new("RGB", (50, 50)))


def test_engine_failure_does_not_leak_engine_output(monkeypatch):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args, 1, b"", b"secret text from the image")

    with pytest.raises(OcrError) as err:
        _engine_with(monkeypatch, fake_run).extract(Image.new("RGB", (50, 50)))
    assert "secret" not in str(err.value)


def test_image_is_sent_on_stdin_with_no_file_paths(monkeypatch):
    seen = {}

    def fake_run(args, **kwargs):
        seen["args"], seen["input"], seen["env"] = args, kwargs["input"], kwargs["env"]
        return subprocess.CompletedProcess(
            args, 0, (HEADER + "\n" + row(5, 1, 1, 1, 90, "Hi")).encode(), b""
        )

    result = _engine_with(monkeypatch, fake_run).extract(Image.new("RGB", (50, 50)))
    assert result.text == "Hi"
    assert seen["args"][1:3] == ["stdin", "stdout"]  # no temporary files
    assert seen["input"].startswith(b"\x89PNG")
    assert seen["env"]["OMP_THREAD_LIMIT"] == "1"


def test_busy_engine(monkeypatch):
    engine = _engine_with(monkeypatch, lambda *a, **k: None)
    engine.timeout = 0.05
    engine._slots = __import__("threading").BoundedSemaphore(1)
    engine._slots.acquire()
    with pytest.raises(OcrBusyError):
        engine.extract(Image.new("RGB", (50, 50)))


@pytest.mark.skipif(not HAS_TESSERACT, reason="Tesseract is not installed")
def test_real_tesseract_reads_text():
    from app.utils.image_validation import validate_image

    image = validate_image(
        render_text(["Share the OTP immediately", "Visit http://example.com/login"]),
        5 * 1024 * 1024,
        25_000_000,
    ).image
    result = TesseractOcrEngine().extract(image)
    assert "Share the OTP immediately" in result.text
    assert "example.com/login" in result.text
    assert result.quality == "good" and result.word_count == 6
