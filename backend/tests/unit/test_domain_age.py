"""Domain registration age over RDAP (all HTTP faked, no network)."""

from datetime import date

import pytest

from app.analyzers import domain_age as da
from app.threat_intelligence.http import HttpResponse, TIHttpError

TODAY = date(2026, 10, 28)
BOOTSTRAP = {
    "services": [
        [["com", "net"], ["https://rdap.verisign.example/com/v1/"]],
        [["org"], ["http://insecure.example/rdap/", "https://rdap.org-registry.example/rdap"]],
        [["onlyhttp"], ["http://insecure.example/"]],
        "garbage",
    ]
}


def rdap(registered: str | None):
    events = [{"eventAction": "last changed", "eventDate": "2026-10-01T00:00:00Z"}]
    if registered:
        events.append({"eventAction": "registration", "eventDate": registered})
    return {"objectClassName": "domain", "events": events}


class RouteHttp:
    """Answers the IANA bootstrap and RDAP URLs from a table; records every request."""

    def __init__(self, routes: dict[str, object], bootstrap: object = BOOTSTRAP) -> None:
        self.routes = {da.BOOTSTRAP_URL: (200, bootstrap), **routes}
        self.requests: list[str] = []

    def request(self, method, url, *, headers=None, body=None, timeout):
        self.requests.append(url)
        answer = self.routes.get(url, (404, None))
        if isinstance(answer, Exception):
            raise answer
        status, data = answer
        return HttpResponse(status, data)


def service(routes, **kwargs):
    http = RouteHttp(routes, **kwargs)
    return da.DomainAgeService(http, enabled=True, today=lambda: TODAY), http


COM = "https://rdap.verisign.example/com/v1/domain/"


def test_bootstrap_keeps_https_servers_only():
    servers = da.parse_bootstrap(BOOTSTRAP)
    assert servers == {
        "com": "https://rdap.verisign.example/com/v1/",
        "net": "https://rdap.verisign.example/com/v1/",
        "org": "https://rdap.org-registry.example/rdap/",
    }
    assert da.parse_bootstrap(None) == {} and da.parse_bootstrap({"services": "x"}) == {}


def test_registration_date_is_read_from_the_registration_event():
    assert da.registration_date(rdap("2026-10-23T10:00:00Z")) == date(2026, 10, 23)
    assert da.registration_date(rdap(None)) is None
    assert (
        da.registration_date({"events": [{"eventAction": "registration", "eventDate": "nope"}]})
        is None
    )
    assert da.registration_date("not json") is None


def test_a_new_domain_is_found_with_its_age():
    svc, http = service({COM + "fresh-offer.com": (200, rdap("2026-10-23T10:00:00Z"))})
    result = svc.lookup("Fresh-Offer.com.")
    assert (result.status, result.age_days, result.registered) == (da.FOUND, 5, date(2026, 10, 23))
    assert result.recently_registered
    # Only IANA and the registry are contacted, and only the domain name is sent.
    assert http.requests == [da.BOOTSTRAP_URL, COM + "fresh-offer.com"]


def test_an_old_domain_is_not_recent():
    svc, _ = service({COM + "example.com": (200, rdap("1995-08-14T04:00:00Z"))})
    result = svc.lookup("example.com")
    assert result.status == da.FOUND and not result.recently_registered
    assert result.age_days == (TODAY - date(1995, 8, 14)).days


@pytest.mark.parametrize(
    ("answer", "status", "detail"),
    [
        ((404, None), da.NOT_FOUND, "the registry has no record of this domain"),
        ((200, rdap(None)), da.NO_DATE, "the registry does not publish a registration date"),
        ((429, None), da.UNAVAILABLE, "rate limited"),
        ((503, None), da.UNAVAILABLE, "registry error"),
        (TIHttpError("timeout"), da.UNAVAILABLE, "timeout"),
    ],
)
def test_registry_answers_and_failures_are_classified(answer, status, detail):
    svc, _ = service({COM + "x.com": answer})
    result = svc.lookup("x.com")
    assert (result.status, result.detail, result.age_days) == (status, detail, None)
    assert not result.recently_registered  # unknown age is never evidence


def test_domain_endings_without_rdap_are_unsupported_without_a_request():
    svc, http = service({})
    assert svc.lookup("example.onlyhttp").status == da.UNSUPPORTED
    assert svc.lookup("example.zz").status == da.UNSUPPORTED
    assert http.requests == [da.BOOTSTRAP_URL]  # the bootstrap is fetched once and reused


def test_without_the_iana_list_the_age_is_unknown():
    svc, _ = service({}, bootstrap=None)
    svc._http.routes[da.BOOTSTRAP_URL] = TIHttpError("network error")
    result = svc.lookup("example.com")
    assert (result.status, result.detail) == (da.UNAVAILABLE, "registry list unavailable")


def test_answers_are_cached_but_failures_are_retried():
    svc, http = service(
        {COM + "a.com": (200, rdap("2020-01-01T00:00:00Z")), COM + "b.com": (429, None)}
    )
    svc.lookup("a.com")
    svc.lookup("a.com")
    svc.lookup("b.com")
    svc.lookup("b.com")
    assert http.requests.count(COM + "a.com") == 1
    assert http.requests.count(COM + "b.com") == 2


def test_a_broken_answer_never_raises():
    svc, _ = service(
        {COM + "a.com": (200, {"events": [{"eventAction": "registration", "eventDate": 5}]})}
    )
    assert svc.lookup("a.com").status == da.NO_DATE


def test_disabled_service_answers_without_any_request():
    http = RouteHttp({})
    svc = da.DomainAgeService(http, enabled=False)
    assert svc.submit("example.com").result().status == da.UNAVAILABLE
    assert http.requests == []
