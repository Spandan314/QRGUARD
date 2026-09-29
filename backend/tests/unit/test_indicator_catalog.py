"""Every indicator ID used in the code or rule files must be defined in scoring_config.yaml
(and every configured ID must be used), so a typo can never reach users as a 500 error."""

import re
from pathlib import Path

from app.analyzers.scam_rules import DERIVED_IDS, load_scam_rules
from app.analyzers.url_rules import load_url_rules
from app.scoring.settings import load_scoring_settings

APP_DIR = Path(__file__).resolve().parents[2] / "app"
ID_PATTERN = re.compile(r'Indicator\(\s*"([A-Z_]+)"|"(TI_[A-Z_]+)"|add\("([A-Z_]+)"')


def ids_used_in_code() -> set[str]:
    found = set()
    for path in APP_DIR.rglob("*.py"):
        for match in ID_PATTERN.finditer(path.read_text(encoding="utf-8")):
            found.add(next(group for group in match.groups() if group))
    rules = load_scam_rules(load_url_rules())
    return found | rules.rule_ids() | set(rules.combinations) | DERIVED_IDS


def test_all_indicator_ids_used_are_configured():
    missing = ids_used_in_code() - set(load_scoring_settings().indicators)
    assert not missing, f"Add these to scoring_config.yaml: {sorted(missing)}"


def test_every_configured_indicator_is_used():
    unused = set(load_scoring_settings().indicators) - ids_used_in_code()
    assert not unused, f"Configured but never emitted: {sorted(unused)}"


def test_message_indicators_belong_to_the_message_module():
    settings = load_scoring_settings()
    for indicator_id, definition in settings.indicators.items():
        assert definition.module == (
            "message" if indicator_id.startswith("MSG_") else definition.module
        )


def test_rule_files_load():
    url_rules = load_url_rules()
    assert "bit.ly" in url_rules.url_shorteners
    assert url_rules.official_domains()["sbi.co.in"].name == "State Bank of India"
    assert "MSG_OTP_REQUEST" in load_scam_rules(url_rules).rule_ids()
