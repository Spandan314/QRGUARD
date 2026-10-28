# Proposal: TLS certificate check (handshake only)

Status: **proposal, not implemented**. Needs the owner's approval because, unlike every check
QRGUARD runs today except shortener redirects, it opens a connection to the website being checked.

## 1. What it would add

For an `https://` link, complete one TLS handshake with the site and report:

| Outcome | Indicator (proposed) | Weight |
|---|---|---|
| Certificate expired or not yet valid | `TLS_CERT_EXPIRED` | 15 |
| Certificate does not cover the hostname | `TLS_HOSTNAME_MISMATCH` | 20 |
| Untrusted chain (self-signed, unknown CA) | `TLS_UNTRUSTED_CERT` | 15 |
| Valid certificate issued < 7 days ago | `TLS_CERT_VERY_NEW` | 5 (info-level evidence) |
| Valid, older certificate | none (a valid certificate is **not** evidence of safety) | 0 |

All of these go into one category, `tls`, capped at 20, so they never stack into a verdict on their
own. "Free automated certificate" (for example Let's Encrypt) is **not** a sign: most legitimate
sites use one.

## 2. Network safety (SSRF)

The design reuses the hardened code QRGUARD already has for shortener redirects
(`app/analyzers/redirect_resolver.py`, `app/utils/net_safety.py`).

1. **Public addresses only.** The host is resolved once with `resolve_host` (bounded DNS
   concurrency, timeout). **Every** returned address must pass `is_public_ip`, which rejects
   loopback, private, link-local (including 169.254.169.254), CGNAT, multicast, reserved and
   NAT64 ranges, and IPv4 addresses hidden inside IPv6. If any address fails, the check is
   `not_run` ("internal address"). No connection is made.
2. **DNS-rebinding protection.** The connection goes to the **already validated IP**, not the
   name: `socket.create_connection((ip, 443))`. The hostname is used only for SNI and for
   certificate validation, so a second, different DNS answer cannot redirect the connection.
3. **Port 443 only.** Links with an explicit port (`URL_NONSTANDARD_PORT`) or `http://` are
   `not_run`. No other port is ever contacted.
4. **No HTTP at all.** After the handshake the socket is closed. No request line, no headers, no
   redirect following and no body are sent or read, so no remote content is downloaded or run.
5. **Limits.** A 3 s connect + handshake deadline, enforced by the existing `_Deadline` watchdog
   (it shuts down the socket even if the TLS library blocks). At most 2 concurrent handshakes per
   worker, sharing `RedirectSlots`; beyond that the check is `not_run` ("busy"). Results are cached
   per hostname for 1 hour, with failures cached briefly to avoid hammering a site.
6. **Opt-in flag.** `TLS_CHECK=false` by default, like `DOMAIN_AGE_LOOKUP`, so production behaviour
   changes only when the owner switches it on. `REDIRECT_RESOLUTION` stays `shorteners_only` and
   is independent.

## 3. Certificate validation

- Use `ssl.create_default_context(cafile=certifi.where())`, which has `CERT_REQUIRED` and
  `check_hostname=True`, for the verdict on the chain and the hostname.
- On `ssl.SSLCertVerificationError`, classify by `verify_code`: expired or not yet valid →
  `TLS_CERT_EXPIRED`; hostname mismatch → `TLS_HOSTNAME_MISMATCH`; anything else (self-signed,
  unknown issuer, incomplete chain) → `TLS_UNTRUSTED_CERT`.
- To read `notBefore` and `notAfter` on success, use `getpeercert()` from the verified socket.
  The certificate details are never fetched by a second, unverified connection.
- No certificate fields other than validity dates and the issuer organisation are stored or shown,
  and none are logged.

## 4. Unknown or failed checks

| Situation | Check status | Effect |
|---|---|---|
| Timeout, connection refused or reset, TLS protocol error not about the certificate | `unavailable` | No points; confidence lowered (as for a failed threat-intelligence provider) |
| Internal address, non-443 port, `http://`, busy, switched off | `not_run` | No points; no confidence change |
| Valid certificate | `completed` | No points; never makes a result SAFE (SAFE still requires the trusted-domain list) |

A missing or failed TLS check never counts as evidence of safety, and never changes SAFE,
SUSPICIOUS, MALICIOUS or UNVERIFIED semantics: it only adds capped evidence or lowers confidence.

## 5. Privacy and policy note

The handshake reveals to the site (and to anyone watching DNS) that QRGUARD looked at it, from the
server's IP address. This is the main reason it needs approval. It sends no URL path, query or user
data: only SNI (the hostname).

## 6. Deterministic tests (no suspicious live sites)

- **Unit tests with a local TLS server.** Start `ssl`-wrapped servers on `127.0.0.1` inside the test
  with generated certificates (the `cryptography` package, already a transitive dependency):
  valid, expired, not-yet-valid, wrong hostname and self-signed. Inject a fake resolver mapping a
  test hostname to the test server, and a test CA file, so the checker's real code path runs
  end to end without the network.
- **SSRF tests.** A fake resolver returns loopback, private, link-local, metadata and mixed
  (one public, one private) addresses; assert no socket is opened (patched
  `socket.create_connection` records calls), and that `http://`, explicit ports and IP literals
  are `not_run`.
- **Rebinding test.** A resolver returns a public IP on the first call and `127.0.0.1` on the
  second; assert the single connection goes to the first, validated IP.
- **Resource tests.** A server that accepts but never completes the handshake must be cut off at
  the deadline; with two slots held, a third check is `not_run` ("busy"); the server must receive
  no bytes after the handshake, which proves no HTTP request was sent.
- **API tests.** Through `/api/analyze/url` with the checker faked: each indicator's points and
  evidence; `unavailable` → LOW confidence and never SAFE; switched off → no check listed and
  no connection.

## 7. Effort

About 1–2 days, including tests: new module `app/analyzers/tls_check.py`, wiring next to the
domain-age lookup in `UrlAnalysisService.collect`, config flag, scoring entries and docs.
