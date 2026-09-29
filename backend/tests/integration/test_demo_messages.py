"""Runs the labelled DEMO / TEST DATA set in demo-data/messages.yaml through the API."""

from pathlib import Path

import pytest
import yaml

from tests.conftest import make_app
from tests.fakes import FakeFetcher, FakeResolver

DEMO_FILE = Path(__file__).resolve().parents[3] / "demo-data" / "messages.yaml"
MESSAGES = yaml.safe_load(DEMO_FILE.read_text(encoding="utf-8"))["messages"]


@pytest.fixture(scope="module")
def client():
    app = make_app()
    service = app.extensions["qrguard.url_analysis"]
    service.fetcher, service.resolver = FakeFetcher(), FakeResolver()
    return app.test_client()


@pytest.mark.parametrize("case", MESSAGES, ids=[m["id"] for m in MESSAGES])
def test_demo_message(client, case):
    body = client.post("/api/analyze/message", json={"text": case["text"]}).get_json()
    assert body["risk_level"] == case["expected_level"], body["indicators"]
    categories = {c["id"] for c in body["categories"]}
    assert set(case.get("expected_categories", [])) <= categories


def test_no_genuine_message_is_malicious_and_no_scam_is_safe(client):
    genuine_scores, scam_levels = [], []
    for case in MESSAGES:
        body = client.post("/api/analyze/message", json={"text": case["text"]}).get_json()
        if case.get("genuine"):
            genuine_scores.append(body["risk_score"])
        else:
            scam_levels.append(body["risk_level"])
    assert max(genuine_scores) < 30  # every genuine message is SAFE
    assert "SAFE" not in scam_levels  # every scam is at least SUSPICIOUS
    assert len(genuine_scores) >= 14 and len(scam_levels) >= 25
