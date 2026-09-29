import pytest
import yaml

from app.scoring.settings import (
    DEFAULT_SCORING_CONFIG_PATH,
    ScoringConfigError,
    load_scoring_settings,
)


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


def test_agreed_floors_and_categories():
    settings = load_scoring_settings()
    assert settings.indicators["TI_LISTED"].floor == 90
    assert settings.indicators["BRAND_LOOKALIKE"].floor >= 60
    assert len(settings.scam_categories) == 14


def _write(tmp_path, data):
    path = tmp_path / "scoring.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


@pytest.fixture
def valid():
    return yaml.safe_load(DEFAULT_SCORING_CONFIG_PATH.read_text(encoding="utf-8"))


def test_thresholds_must_be_ordered(tmp_path, valid):
    valid["thresholds"] = {"suspicious": 70, "malicious": 60}
    with pytest.raises(ScoringConfigError, match="lower than"):
        load_scoring_settings(_write(tmp_path, valid))


def test_weights_must_sum_to_one(tmp_path, valid):
    valid["module_weights"]["url_qr"] = 0.5
    with pytest.raises(ScoringConfigError, match="add up to 1.0"):
        load_scoring_settings(_write(tmp_path, valid))


def test_indicator_with_unknown_category_rejected(tmp_path, valid):
    valid["indicators"]["URL_IP_HOST"]["category"] = "nonsense"
    with pytest.raises(ScoringConfigError, match="unknown category"):
        load_scoring_settings(_write(tmp_path, valid))


def test_indicator_with_unknown_scam_category_rejected(tmp_path, valid):
    valid["indicators"]["URL_IP_HOST"]["scam_categories"] = ["crypto_heist"]
    with pytest.raises(ScoringConfigError, match="unknown scam category"):
        load_scoring_settings(_write(tmp_path, valid))


def test_verification_indicators_must_exist(tmp_path, valid):
    valid["verification"]["trusted_domain_indicator"] = "NOPE"
    with pytest.raises(ScoringConfigError, match="trusted_domain_indicator"):
        load_scoring_settings(_write(tmp_path, valid))


def test_unknown_keys_rejected(tmp_path, valid):
    valid["thresholds"]["extreme"] = 90
    with pytest.raises(ScoringConfigError):
        load_scoring_settings(_write(tmp_path, valid))


def test_missing_file(tmp_path):
    with pytest.raises(ScoringConfigError, match="not found"):
        load_scoring_settings(tmp_path / "nope.yaml")


def test_invalid_yaml(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("version: [1, 2\n", encoding="utf-8")
    with pytest.raises(ScoringConfigError):
        load_scoring_settings(path)
