"""The final-demonstration kit: every scenario gives the result the runbook promises."""

import shutil
from pathlib import Path

from PIL import Image

from scripts import demo_kit


def test_every_demo_scenario_gives_the_documented_result():
    include_screenshots = shutil.which("tesseract") is not None  # installed in CI
    assert demo_kit.check(include_screenshots=include_screenshots) == []


def test_written_qr_codes_decode_to_the_same_verdicts(tmp_path: Path):
    demo_kit.write(tmp_path)
    qr_scenarios = [s for s in demo_kit.SCENARIOS if s.kind == "qr"]
    assert sorted(p.name for p in tmp_path.glob("qr-*.png")) == [
        f"qr-{s.number:02d}.png" for s in qr_scenarios
    ]
    assert "DEMO / TEST DATA" in (tmp_path / "index.html").read_text(encoding="utf-8")

    client = demo_kit._client()
    for scenario in qr_scenarios:
        path = tmp_path / f"qr-{scenario.number:02d}.png"
        assert Image.open(path).size[0] >= 200
        with path.open("rb") as image:
            body = client.post(
                "/api/analyze/qr",
                data={"file": (image, path.name)},
                content_type="multipart/form-data",
            ).get_json()
        assert body["risk_level"] == scenario.expected, scenario.title
