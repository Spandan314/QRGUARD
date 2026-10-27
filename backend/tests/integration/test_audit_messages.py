"""Message audit set (demo-data/evaluation/audit-2026-10.yaml) as a regression test.

Every scam family must be at least SUSPICIOUS with a stated reason, and no genuine message that
merely uses alarming words (OTP, bank, urgent, refund, KYC) may be rated MALICIOUS. The rules were
adjusted after the first measurement of this set (docs/evaluation.md), so it is in-sample now; the
untouched hold-out set remains the honest estimate.
"""

from pathlib import Path

import pytest
import yaml

from tests.conftest import make_app

ITEMS = yaml.safe_load(
    (Path(__file__).resolve().parents[3] / "demo-data/evaluation/audit-2026-10.yaml").read_text(
        encoding="utf-8"
    )
)["messages"]


@pytest.fixture(scope="module")
def client():
    return make_app(REDIRECT_RESOLUTION="off").test_client()


@pytest.mark.parametrize("item", [i for i in ITEMS if i["label"] == "scam"], ids=lambda i: i["id"])
def test_every_scam_family_is_flagged_with_reasons(client, item):
    body = client.post("/api/analyze/message", json={"text": item["text"]}).get_json()
    assert body["risk_level"] in ("SUSPICIOUS", "MALICIOUS"), (item["family"], body["risk_score"])
    assert body["categories"] and any(i["score_contribution"] > 0 for i in body["indicators"])


@pytest.mark.parametrize(
    "item", [i for i in ITEMS if i["label"] == "genuine"], ids=lambda i: i["id"]
)
def test_genuine_messages_with_alarming_words_are_not_malicious(client, item):
    body = client.post("/api/analyze/message", json={"text": item["text"]}).get_json()
    assert body["risk_level"] != "MALICIOUS"
    assert body["verdict"]["label"] in ("UNVERIFIED", "SUSPICIOUS")  # never "SAFE" for a message
