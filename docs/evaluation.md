# Evaluation

How well does QRGUARD separate scams from genuine content? This page reports measured numbers,
how they were produced, and where the system fails.

## Method

```bash
cd backend
python -m scripts.evaluate --json /tmp/qrguard-eval.json
```

`scripts/evaluate.py` sends every labelled item through the **real API** (Flask test client),
so it uses the same analysis, threat-intelligence and scoring code as production. Redirect
checking is turned off so that no link is contacted and results are repeatable. Only the local
demo blocklist is used for threat intelligence; external providers are off.

A result counts as a **positive** (flagged) when it is SUSPICIOUS or MALICIOUS.

| Data set | File | Role |
|---|---|---|
| Held-out | `demo-data/evaluation/holdout.yaml` | 24 messages + 24 URLs written **after** the rules were frozen, never used for tuning |
| Tuning | `demo-data/messages.yaml` | 39 messages used while writing the rules (in-sample, so optimistic) |

All items are synthetic DEMO / TEST DATA (no real people's data; reserved or fake domains).

## Results (engine 0.1.0, scoring config v2)

| Set | Items (scam/genuine) | Recall | Precision | F1 | Accuracy | False alarms | Missed | Genuine → MALICIOUS |
|---|---|---|---|---|---|---|---|---|
| Held-out messages | 24 (12/12) | 0.833 | 0.909 | 0.870 | 0.875 | 1 | 2 | 0 |
| Held-out URLs | 24 (12/12) | 0.917 | 1.000 | 0.957 | 0.958 | 0 | 1 | 0 |
| Tuning messages (in-sample) | 39 (25/14) | 1.000 | 1.000 | 1.000 | 1.000 | 0 | 0 | 0 |

Confusion (held-out):

| | SAFE | SUSPICIOUS | MALICIOUS |
|---|---|---|---|
| Scam messages | 2 | 3 | 7 |
| Genuine messages | 11 | 1 | 0 |
| Scam URLs | 1 | 7 | 4 |
| Genuine URLs | 12 | 0 | 0 |

The in-sample tuning score of 1.000 is **not** a measure of real-world accuracy: the rules were
written with those messages in view. The held-out numbers are the honest ones, and even they come
from a small synthetic set (48 items), so each error moves the rates by about 4–8 points.

## Errors on the held-out set

| Item | Result | Why |
|---|---|---|
| `m-crypto-doubling` (scam) | SAFE 10 | Only "investment topic" and "off-platform contact" fired. There is no rule for *guaranteed / multiplied returns* ("guaranteed Rs 50,000 in 7 days"). |
| `m-gift-card-boss` (scam) | SAFE 15 | Boss/CEO gift-card fraud has no rule. Only urgency fired. |
| `m-delivery-otp` (genuine) | SUSPICIOUS 30 | "Share OTP … with the delivery partner" matches the OTP-request rule. Genuine delivery OTPs do ask this. |
| `u-port` (scam) | SAFE 28 | Non-standard port + no HTTPS + keywords add up to 28, just under the SUSPICIOUS threshold (30). |

No genuine item was rated MALICIOUS on either set, and every scam that fired a strong indicator
(brand impersonation, credential/UPI-PIN request, threat-intelligence hit, IP host, punycode,
userinfo trick, APK download) was flagged.

These gaps are recorded here rather than "fixed" by changing weights until the numbers look good.
Any new rule (for example guaranteed-returns wording, gift-card requests from a "manager", or a
narrower OTP rule that allows "share only with the delivery partner") must be evaluated on a
**new** held-out set, because this one has now been seen.

## What SAFE means

SAFE means "no significant indicators were found", not "verified safe". The API and both apps
always show the verification status separately (UNVERIFIED unless a trusted source confirms it),
and the SAFE summary says it does not guarantee safety. The missed items above are exactly why.

## Performance

Measured in the test client on a development container (no network): message analysis takes about
1–3 ms, URL analysis about 5–10 ms. In production, time is dominated by optional redirect checks
(≤ 8 s budget), external threat-intelligence lookups (3 s timeout each, 6 s total budget) and OCR
(≤ 20 s).

## Reproducing

`tests/unit/test_evaluate.py` checks the metric arithmetic and that every item in both sets
is analysed without errors and no genuine item is MALICIOUS. It does **not** assert recall or
precision targets, so the rules cannot be tuned to a test.
