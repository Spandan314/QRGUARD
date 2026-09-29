"""`flask --app wsgi ti-update-feeds`: download public blocklists into THREAT_INTEL_FEED_DIR.

Run it at deploy time or from a scheduled job, then restart the app (feeds are loaded at
startup). Only the fixed feed URLs below are contacted. Each download is capped in size and
written atomically; a failed download keeps the previous file.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import certifi
import click
import urllib3
from flask import current_app
from flask.cli import with_appcontext

FEEDS = {
    # Community feeds (non-commercial use; check each provider's terms before deploying).
    "openphish.txt": "https://openphish.com/feed.txt",
    "urlhaus_recent.txt": "https://urlhaus.abuse.ch/downloads/text_recent/",
}
MAX_FEED_BYTES = 50 * 1024 * 1024


def download(url: str, target: Path, pool: urllib3.PoolManager) -> int:
    response = pool.request(
        "GET",
        url,
        timeout=urllib3.Timeout(connect=10, read=30),
        retries=False,
        redirect=False,
        preload_content=False,
    )
    try:
        if response.status != 200:
            raise click.ClickException(f"{target.name}: HTTP {response.status}")
        data = response.read(MAX_FEED_BYTES + 1)
    finally:
        response.release_conn()
    if len(data) > MAX_FEED_BYTES:
        raise click.ClickException(f"{target.name}: feed larger than {MAX_FEED_BYTES} bytes")
    fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".part")
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.replace(tmp, target)
    return sum(1 for line in data.splitlines() if line.strip() and not line.startswith(b"#"))


@click.command("ti-update-feeds")
@with_appcontext
def update_feeds_command() -> None:
    """Download the OpenPhish and URLhaus plain-text feeds into THREAT_INTEL_FEED_DIR."""
    feed_dir = current_app.config["QRGUARD"].ti_feed_dir
    if not feed_dir:
        raise click.ClickException("Set THREAT_INTEL_FEED_DIR to the folder for the feed files.")
    directory = Path(feed_dir)
    directory.mkdir(parents=True, exist_ok=True)
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED", ca_certs=certifi.where())
    failures = 0
    for name, url in FEEDS.items():
        try:
            count = download(url, directory / name, pool)
            click.echo(f"{name}: {count} entries")
        except (urllib3.exceptions.HTTPError, click.ClickException) as exc:
            failures += 1
            message = exc.message if isinstance(exc, click.ClickException) else "network error"
            click.echo(f"{name}: not updated ({message})", err=True)
    if failures == len(FEEDS):
        raise click.ClickException("No feed could be downloaded.")
