"""Measure detection quality on the labelled DEMO / TEST DATA sets.

    cd backend && python -m scripts.evaluate [--json out.json]

Every item goes through the real API (Flask test client): the same analysis, threat-intelligence
and scoring code as production. Redirect checking is off so results are deterministic and no link
is contacted. Positive = SUSPICIOUS or MALICIOUS.

Sets:
  holdout  demo-data/evaluation/holdout.yaml  written after the rules were frozen, never tuned on
  tuning   demo-data/messages.yaml            used while writing the rules (in-sample, optimistic)
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from app import create_app
from app.config import Config

ROOT = Path(__file__).resolve().parents[2]
LEVELS = ("SAFE", "SUSPICIOUS", "MALICIOUS")


def _client():
    config = Config.from_env(
        {
            "APP_ENV": "testing",
            "REDIRECT_RESOLUTION": "off",
            "HISTORY_STORE": "off",
            "RATELIMIT_DEFAULT": "100000 per minute",
            "RATELIMIT_ANALYZE": "100000 per minute",
        }
    )
    return create_app(config).test_client()


def _run(client, kind: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in items:
        if kind == "message":
            response = client.post("/api/analyze/message", json={"text": item["text"]})
        else:
            response = client.post("/api/analyze/url", json={"url": item["url"]})
        body = response.get_json()
        level = body.get("risk_level") if response.status_code == 200 else "ERROR"
        rows.append(
            {
                "id": item["id"],
                "label": item["label"],
                "level": level,
                "score": body.get("risk_score"),
                "verification": (body.get("verification") or {}).get("status"),
            }
        )
    return rows


def _describe(row: dict[str, Any]) -> str:
    return f"{row['id']} ({row['level']} {row['score']})"


def metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    scams = [r for r in rows if r["label"] == "scam"]
    genuine = [r for r in rows if r["label"] == "genuine"]
    positive = {"SUSPICIOUS", "MALICIOUS"}
    tp = sum(r["level"] in positive for r in scams)
    fn = len(scams) - tp
    fp = sum(r["level"] in positive for r in genuine)
    tn = len(genuine) - fp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(scams) if scams else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "items": len(rows),
        "scams": len(scams),
        "genuine": len(genuine),
        "confusion": {
            label: dict(Counter(r["level"] for r in rows if r["label"] == label))
            for label in ("scam", "genuine")
        },
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "accuracy": round((tp + tn) / len(rows), 3) if rows else 0.0,
        "scams_malicious": sum(r["level"] == "MALICIOUS" for r in scams),
        "genuine_malicious": sum(r["level"] == "MALICIOUS" for r in genuine),
        "errors": sum(r["level"] == "ERROR" for r in rows),
        "missed": [_describe(r) for r in scams if r["level"] not in positive],
        "false_alarms": [_describe(r) for r in genuine if r["level"] in positive],
    }


def _tuning_items() -> list[dict[str, Any]]:
    data = yaml.safe_load((ROOT / "demo-data" / "messages.yaml").read_text(encoding="utf-8"))
    return [
        {"id": m["id"], "label": "genuine" if m.get("genuine") else "scam", "text": m["text"]}
        for m in data["messages"]
    ]


def evaluate() -> dict[str, Any]:
    client = _client()
    holdout = yaml.safe_load(
        (ROOT / "demo-data" / "evaluation" / "holdout.yaml").read_text(encoding="utf-8")
    )
    runs = {
        "holdout_messages": _run(client, "message", holdout["messages"]),
        "holdout_urls": _run(client, "url", holdout["urls"]),
        "tuning_messages": _run(client, "message", _tuning_items()),
    }
    return {name: {"metrics": metrics(rows), "rows": rows} for name, rows in runs.items()}


def _print(report: dict[str, Any]) -> None:
    print(
        "| Set | Items (scam/genuine) | Recall | Precision | F1 | Accuracy | FP | FN "
        "| Genuine→MALICIOUS |"
    )
    print("|" + "---|" * 9)
    for name, result in report.items():
        m = result["metrics"]
        print(
            f"| {name} | {m['items']} ({m['scams']}/{m['genuine']}) | {m['recall']:.3f} | "
            f"{m['precision']:.3f} | {m['f1']:.3f} | {m['accuracy']:.3f} | {m['fp']} | {m['fn']} | "
            f"{m['genuine_malicious']} |"
        )
    for name, result in report.items():
        m = result["metrics"]
        print(f"\n{name}: confusion {m['confusion']}")
        if m["missed"]:
            print(f"  missed scams: {', '.join(m['missed'])}")
        if m["false_alarms"]:
            print(f"  false alarms: {', '.join(m['false_alarms'])}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--json", type=Path, help="also write the full results to this file")
    args = parser.parse_args()
    report = evaluate()
    _print(report)
    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
