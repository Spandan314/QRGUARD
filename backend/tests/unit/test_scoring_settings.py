import pytest

from app.scoring.settings import ScoringConfigError, load_scoring_settings


def test_default_scoring_file_matches_agreed_values():
    settings = load_scoring_settings()
    assert settings.thresholds.suspicious == 30
    assert settings.thresholds.malicious == 60
    weights = settings.module_weights
    assert (weights.url_qr, weights.threat_intel, weights.message, weights.ocr) == (
        0.35,
        0.30,
        0.20,
        0.15,
    )


def _write(tmp_path, body: str):
    path = tmp_path / "scoring.yaml"
    path.write_text(body, encoding="utf-8")
    return path


VALID_WEIGHTS = "module_weights: {url_qr: 0.35, threat_intel: 0.3, message: 0.2, ocr: 0.15}\n"


def test_thresholds_must_be_ordered(tmp_path):
    path = _write(
        tmp_path, "version: 1\nthresholds: {suspicious: 70, malicious: 60}\n" + VALID_WEIGHTS
    )
    with pytest.raises(ScoringConfigError, match="lower than"):
        load_scoring_settings(path)


def test_weights_must_sum_to_one(tmp_path):
    path = _write(
        tmp_path,
        "version: 1\nthresholds: {suspicious: 30, malicious: 60}\n"
        "module_weights: {url_qr: 0.5, threat_intel: 0.3, message: 0.2, ocr: 0.15}\n",
    )
    with pytest.raises(ScoringConfigError, match="add up to 1.0"):
        load_scoring_settings(path)


def test_unknown_keys_rejected(tmp_path):
    path = _write(
        tmp_path,
        "version: 1\nthresholds: {suspicious: 30, malicious: 60, extreme: 90}\n" + VALID_WEIGHTS,
    )
    with pytest.raises(ScoringConfigError):
        load_scoring_settings(path)


def test_missing_file(tmp_path):
    with pytest.raises(ScoringConfigError, match="not found"):
        load_scoring_settings(tmp_path / "nope.yaml")


def test_invalid_yaml(tmp_path):
    with pytest.raises(ScoringConfigError):
        load_scoring_settings(_write(tmp_path, "version: [1, 2\n"))
