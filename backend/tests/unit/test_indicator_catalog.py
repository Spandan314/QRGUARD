"""Every indicator ID used in the code must be defined in scoring_config.yaml (and vice versa
for the URL module), so a typo can never reach users as a 500 error."""

import re
from pathlib import Path

from app.analyzers.url_rules import load_url_rules
from app.scoring.settings import load_scoring_settings

APP_DIR = Path(__file__).resolve().parents[2] / "app"
ID_PATTERN = re.compile(r'Indicator\(\s*"([A-Z_]+)"|"((?:TI)_[A-Z_]+)"')


def ids_used_in_code() -> set[str]:
    found = set()
    for path in APP_DIR.rglob("*.py"):
        for match in ID_PATTERN.finditer(path.read_text(encoding="utf-8")):
            found.add(match.group(1) or match.group(2))
    add_calls = re.compile(r'add\("([A-Z_]+)"')  # lookalike.py helper
    for path in APP_DIR.rglob("*.py"):
        found.update(add_calls.findall(path.read_text(encoding="utf-8")))
    return found


def test_all_indicator_ids_used_in_code_are_configured():
    configured = set(load_scoring_settings().indicators)
    missing = ids_used_in_code() - configured
    assert not missing, f"Add these to scoring_config.yaml: {sorted(missing)}"


def test_every_url_indicator_in_config_is_used():
    settings = load_scoring_settings()
    url_ids = {k for k, v in settings.indicators.items() if v.module in ("url_qr", "threat_intel")}
    unused = url_ids - ids_used_in_code()
    assert not unused, f"Configured but never emitted: {sorted(unused)}"


def test_url_rule_files_load():
    rules = load_url_rules()
    assert "bit.ly" in rules.url_shorteners
    assert rules.official_domains()["sbi.co.in"].name == "State Bank of India"
