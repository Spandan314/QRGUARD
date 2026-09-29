"""Minimal HTTPS client for threat-intelligence APIs.

Only fixed, well-known provider hosts are contacted (never user-supplied hosts), always over
verified HTTPS, with a strict timeout, no retries, no redirects and a cap on the response
size. Errors never include the request (URLs, API keys) in their message.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

import certifi
import urllib3

MAX_RESPONSE_BYTES = 1024 * 1024


class TIHttpError(Exception):
    """Network failure, timeout or an unreadable response (message is always generic)."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    data: Any  # parsed JSON, or None when the body was empty / not JSON


class HttpClient(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float,
    ) -> HttpResponse: ...


class Urllib3Client:
    def __init__(self) -> None:
        self._pool = urllib3.PoolManager(
            cert_reqs="CERT_REQUIRED", ca_certs=certifi.where(), num_pools=4, maxsize=4
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float,
    ) -> HttpResponse:
        try:
            response = self._pool.request(
                method,
                url,
                headers={"User-Agent": "QRGUARD/1.0", **(headers or {})},
                body=body,
                timeout=urllib3.Timeout(connect=timeout, read=timeout),
                retries=False,
                redirect=False,
                preload_content=False,
            )
            try:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            finally:
                response.release_conn()
        except urllib3.exceptions.HTTPError:
            # "from None": the original exception text can contain the request URL (and so a
            # query-string API key), which must never reach logs or responses.
            raise TIHttpError("network error") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise TIHttpError("response too large")
        try:
            data = json.loads(raw) if raw else None
        except ValueError:
            data = None
        return HttpResponse(response.status, data)
