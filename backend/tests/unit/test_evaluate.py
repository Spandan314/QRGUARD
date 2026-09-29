"""The evaluation script: metric arithmetic and a smoke run over the labelled data sets."""

from scripts.evaluate import evaluate, metrics


def test_metrics_arithmetic():
    rows = [
        {"id": "s1", "label": "scam", "level": "MALICIOUS", "score": 80},
        {"id": "s2", "label": "scam", "level": "SUSPICIOUS", "score": 40},
        {"id": "s3", "label": "scam", "level": "SAFE", "score": 10},
        {"id": "g1", "label": "genuine", "level": "SAFE", "score": 0},
        {"id": "g2", "label": "genuine", "level": "SUSPICIOUS", "score": 35},
    ]
    m = metrics(rows)
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (2, 1, 1, 1)
    assert m["precision"] == 0.667 and m["recall"] == 0.667 and m["f1"] == 0.667
    assert m["accuracy"] == 0.6
    assert m["missed"] == ["s3 (SAFE 10)"] and m["false_alarms"] == ["g2 (SUSPICIOUS 35)"]
    assert m["confusion"]["scam"] == {"MALICIOUS": 1, "SUSPICIOUS": 1, "SAFE": 1}


def test_metrics_of_an_empty_set():
    assert metrics([])["f1"] == 0.0


def test_every_item_is_analysed():
    report = evaluate()
    assert set(report) == {"holdout_messages", "holdout_urls", "tuning_messages"}
    for result in report.values():
        assert result["metrics"]["errors"] == 0
        assert result["metrics"]["genuine_malicious"] == 0
