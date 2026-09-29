# Proposal: Scam Message Detector

> **Status: APPROVED and IMPLEMENTED.** The authoritative description is now
> `docs/risk-scoring.md` section 11. Differences from this proposal:
> - `MSG_COMBO_THREAT_URGENCY_LINK` became `MSG_COMBO_THREAT_URGENCY_ACTION`: a link **or** a
>   phone-number call-to-action completes it (electricity-disconnection scams use a phone number).
> - `MSG_SECURITY_ADVICE` also recognises "you don't need to pay any fee" style statements.
> - The overlap rule (one piece of text supports one indicator) was added to prevent double
>   counting. As a result the lottery example scores 50 (SUSPICIOUS), not the 65 predicted below.
> - Responses add `source` per indicator and `score_breakdown.sources`.

Same philosophy as the URL module: explainable, rule-based, configurable, multi-label categories,
and no single keyword can make a message MALICIOUS. Indicators produce the score; categories only
describe it.

Files to be created after approval:

| File | Content |
|---|---|
| `app/data/scam_rules.yaml` | Phrase patterns, negation cues, combination rules (data, editable) |
| `app/analyzers/text_preprocessor.py` | Section 4 pipeline |
| `app/analyzers/message_analyzer.py` | Pattern matching, negation, combinations → indicators |
| `app/services/message_analysis_service.py` | Message + links (reuses the URL service) → scoring |
| `app/scoring/scoring_config.yaml` | + `MSG_*` indicators (weights stay in this one file) |

---

## 1. Feature / indicator catalogue (module `message`)

Each indicator fires on a **phrase-level pattern** (a verb and object, or word combinations within a
small window), not on isolated words wherever possible. Evidence is the matched phrase (≤ 60
characters), returned to the caller only; it is never logged or stored.

### Pressure (category cap 20)

| ID | Detects (examples) | Weight |
|---|---|---|
| `MSG_URGENCY` | "immediately", "within 24 hours", "today only", "last chance", "act now", "expires today" | 10 |
| `MSG_ACCOUNT_THREAT` | "account will be blocked/suspended/deactivated", "SIM will be blocked", "card will be closed" | 15 |
| `MSG_LEGAL_THREAT` | "legal action", "arrest warrant", "FIR", "police case", "penalty", "electricity will be disconnected tonight" | 15 |

### Credential and payment-authorisation requests (category cap 40)

| ID | Detects | Weight |
|---|---|---|
| `MSG_OTP_REQUEST` | share/send/tell/forward/give **→** OTP / verification code (within 4 words) | 30 |
| `MSG_CREDENTIAL_REQUEST` | share/enter/confirm **→** password, PIN, MPIN, CVV, card number, net-banking login, full Aadhaar/PAN | 30 |
| `MSG_UPI_PIN_TO_RECEIVE` | "enter UPI PIN to receive", "accept the collect request to get refund", "scan QR to receive money" | 30 |
| `MSG_REMOTE_ACCESS` | AnyDesk, TeamViewer, QuickSupport, RustDesk, "screen share", "install this app to verify" | 25 |

### Financial requests (category cap 30)

| ID | Detects | Weight |
|---|---|---|
| `MSG_PAYMENT_REQUEST` | "pay", "transfer", "send money", "deposit" + an amount or payee | 15 |
| `MSG_UPFRONT_FEE` | registration / processing / verification fee, refundable security deposit, customs or courier charges, "tax to release your prize" | 15 |

### Pretexts (category cap 20)

| ID | Detects | Weight |
|---|---|---|
| `MSG_KYC_PRETEXT` | "update your KYC", "KYC expired/pending", "re-KYC", "PAN/Aadhaar not linked" | 15 |
| `MSG_REFUND_PRETEXT` | "refund initiated", "excess amount credited", "income-tax refund approved" | 10 |

### Lures (category cap 25)

| ID | Detects | Weight |
|---|---|---|
| `MSG_PRIZE_REWARD` | "you have won", lottery, lucky draw, jackpot, "cashback of ₹X", "selected for a gift" | 15 |
| `MSG_JOB_LURE` | "work from home", "part-time job", "earn ₹X per day", "daily income", "no experience needed" | 15 |
| `MSG_TASK_EARNING` | "like YouTube videos", "rate products", "Telegram task", "prepaid task" | 15 |
| `MSG_INTERNSHIP_LURE` | internship + (stipend / offer letter / certificate) + selection without an interview | 15 |
| `MSG_UNREALISTIC_RETURNS` | "guaranteed returns", "double your money", "X% daily profit", "risk-free" | 20 |
| `MSG_INVESTMENT_TOPIC` | crypto, forex, trading tips, "VIP group", "stock tips" | 5 |

### Impersonation / context references (category cap 20)

These are context signals with **low** weights: genuine messages mention banks too. They matter
mainly through the combination rules below.

| ID | Detects | Weight |
|---|---|---|
| `MSG_BANK_REFERENCE` | bank/payment brand names (reused from `brands.yaml`), "your bank", RBI, NPCI | 5 |
| `MSG_AUTHORITY_REFERENCE` | police, CBI, customs, income-tax department, TRAI, court, cyber cell, electricity board | 10 |
| `MSG_SUPPORT_REFERENCE` | "customer care", "helpline", "support team", "executive", "call this number for refund" | 5 |

### Contact, link and style signals (each category cap 10)

| ID | Category | Detects | Weight |
|---|---|---|---|
| `MSG_OFF_PLATFORM_CONTACT` | contact | "WhatsApp me", "join Telegram", "DM on Instagram" | 5 |
| `MSG_PHONE_CALL_TO_ACTION` | contact | a phone number **and** "call/WhatsApp now" **and** pressure, lure or pretext in the same message | 5 |
| `MSG_LINK_CALL_TO_ACTION` | link | a URL in the same sentence as an action verb: click / tap / visit / open / update / verify / log in / claim | 10 |
| `MSG_EXCESSIVE_PUNCTUATION` | style | "!!!" or ≥ 4 "!" | 5 |
| `MSG_EXCESSIVE_CAPS` | style | > 30 % capital letters (in ≥ 20 letters) | 5 |
| `MSG_HIDDEN_CHARACTERS` | style | zero-width or bidirectional control characters, or mixed-alphabet words | 10 |

### Legitimacy signal (category `trust`, not capped)

| ID | Detects | Weight |
|---|---|---|
| `MSG_SECURITY_ADVICE` | "never share your OTP", "do not share this code", "bank will never ask for your PIN" | −10 |

**Negation handling:** if a sentence contains a negation cue (never, do not, don't, will not,
won't, no one…) before the credential verb, then `MSG_OTP_REQUEST` / `MSG_CREDENTIAL_REQUEST` are
**suppressed** for that sentence and `MSG_SECURITY_ADVICE` fires instead. So *"123456 is your OTP.
Do not share it with anyone."* is correctly treated as a genuine message.

### Combination indicators (category `combination`, cap 40)

Each combination is a separate indicator, so it appears in the "Why?" list. They are defined in
`scam_rules.yaml` as groups: each group is any-of, and all groups must match.

| ID | Condition | Weight |
|---|---|---|
| `MSG_COMBO_CREDENTIAL_IMPERSONATION` | {OTP / credential / UPI-PIN request} + {bank / authority / support reference or KYC pretext} | 20 |
| `MSG_COMBO_ADVANCE_FEE` | {prize / job / task / internship lure} + {upfront fee or payment request} | 20 |
| `MSG_COMBO_REWARD_CREDENTIAL` | {prize or refund} + {OTP / credential / UPI-PIN request} | 20 |
| `MSG_COMBO_THREAT_URGENCY_LINK` | {account or legal threat} + urgency + link | 15 |
| `MSG_COMBO_REMOTE_SUPPORT` | remote-access app + {support reference or refund pretext} | 20 |
| `MSG_COMBO_RETURNS_PRIVATE_GROUP` | unrealistic returns + off-platform contact | 15 |

### Safety properties (enforced by tests)

- The largest single indicator is 30, and the largest single category cap is 40. **No single
  keyword or category can reach MALICIOUS (≥ 60).** MALICIOUS needs at least two independent
  categories, a combination rule, or a dangerous link.
- Only explicit **requests** (OTP, credential, UPI PIN) reach SUSPICIOUS (30) on their own. Every
  other single indicator stays SAFE.
- **No floors in the message module.** Floors still come from links: a look-alike bank link sets
  at least 60, and a threat-intel listing sets at least 90.

---

## 2. Scam categories

All 14 are kept. Categories come from the indicators that contributed and are shown **only for
SUSPICIOUS or MALICIOUS** results. They never add points. Several can apply to one message.

| Category | Supporting indicators |
|---|---|
| Phishing | `MSG_LINK_CALL_TO_ACTION`, `MSG_COMBO_THREAT_URGENCY_LINK`, phishing-type URL indicators |
| OTP scam | `MSG_OTP_REQUEST` |
| Banking / payment scam | `MSG_BANK_REFERENCE`, `MSG_PAYMENT_REQUEST`, `MSG_REFUND_PRETEXT` |
| UPI scam | `MSG_UPI_PIN_TO_RECEIVE` |
| KYC / account suspension scam | `MSG_KYC_PRETEXT`, `MSG_ACCOUNT_THREAT` |
| Lottery / prize scam | `MSG_PRIZE_REWARD` |
| Fake job scam | `MSG_JOB_LURE`, `MSG_TASK_EARNING` |
| Fake internship scam | `MSG_INTERNSHIP_LURE` |
| Investment / financial scam | `MSG_UNREALISTIC_RETURNS`, `MSG_INVESTMENT_TOPIC` |
| Impersonation scam | `MSG_AUTHORITY_REFERENCE`, `MSG_COMBO_CREDENTIAL_IMPERSONATION`, brand URL indicators |
| Fake customer support scam | `MSG_SUPPORT_REFERENCE`, `MSG_REMOTE_ACCESS`, `MSG_COMBO_REMOTE_SUPPORT` |
| Credential theft | `MSG_CREDENTIAL_REQUEST`, `MSG_OTP_REQUEST`, `MSG_COMBO_CREDENTIAL_IMPERSONATION` |
| Malicious / suspicious URL | URL-module indicators for links found in the message |
| Other social-engineering scam | **Fallback:** added when the result is SUSPICIOUS/MALICIOUS but no specific category applies (e.g. pressure + style signals only) |

---

## 3. Scoring contribution

**No change to the methodology.** The message module uses the same engine, the same caps/floors
mechanism and the same thresholds (0–29 / 30–59 / 60–100), with module weights message 0.20 and
url_qr 0.35. The table below shows the maximum each category can add to the message module score:

| Category | Cap |
|---|---|
| pressure | 20 |
| credential | 40 |
| financial | 30 |
| pretext | 20 |
| lure | 25 |
| impersonation | 20 |
| contact | 10 |
| link | 10 |
| style | 10 |
| combination | 40 |

The message module score is clamped at 100.

### One decision needed: links inside messages must not dilute the text evidence

With a plain weighted average, a strongly scammy text (message = 80) that contains an ordinary,
clean-looking link (url_qr = 0) would score (0.20×80 + 0.35×0) / 0.55 = **29, SAFE**. That is the
same "absence of evidence counted as safety" problem we already ruled out for threat intelligence.

**Proposed rule (recommended):** for a message, the text is the *primary* module. Links found in
it (url_qr, plus threat_intel when available) are *secondary* evidence and can only **raise** the
score, never lower it:

```
final = max( primary_score , weighted average over primary + secondary modules , floors )
```

The weights are unchanged whenever the link adds risk. This matches the documented principle that
missing or neutral evidence in one module never cancels real evidence in another.
`score_breakdown` will show both numbers and which one was used.

| Example | Message | Link | Plain average | With the rule |
|---|---|---|---|---|
| Scam text, neutral link | 80 | 0 | 29 (SAFE) | **80** (MALICIOUS) |
| Mild text, bad link | 20 | 58 | 44 | **44** (SUSPICIOUS) |
| Scam text, look-alike link | 65 | 60 (+ floor 60) | 62 | **65** (MALICIOUS) |

The alternative, if you prefer, is the plain average with no change. I'd advise against it
because of the first row.

### Verification for messages

A message is VERIFIED only through **threat intelligence** (a link in it is listed as malicious).
A trusted-domain link inside a message does **not** verify the message, because scams often include
genuine links. Otherwise the message is UNVERIFIED. As before, verification never changes the score.

### Predicted results for key examples (indicative; weights are tuned in Week 8)

| Message (DEMO / TEST DATA) | Main indicators | Predicted |
|---|---|---|
| "123456 is your OTP for HDFC Bank login. Never share it with anyone." | bank ref 5, security advice −10 | **0, SAFE** |
| "Rs 2,000 debited from A/c XX1234. If not done by you call 1800-xxx-xxxx. -SBI" | bank ref 5 | **5, SAFE** |
| "Your interview is scheduled on 12 Oct at 11 AM. Please bring your ID." | none | **0, SAFE** |
| "URGENT!!!" | urgency 10, punctuation 5 | **15, SAFE** (single keyword ≠ malicious) |
| "Please share the OTP you just received." | OTP request 30 | **30, SUSPICIOUS** |
| "Dear customer your SBI account will be BLOCKED today. Update KYC immediately: http://sbi-kyc-update.xyz/login" | threat + urgency (capped 20), KYC 15, bank 5, link CTA 10 ("Update … : link"), combo 15 = 65; link 58 → weighted 62.5 | **65, MALICIOUS** |
| "Part-time job! Earn ₹3000/day liking YouTube videos. Registration fee ₹499. WhatsApp 98xxxxxx12" | job 15 + task 15 (capped 25), fee 15, off-platform 5, advance-fee combo 20 | **65, MALICIOUS** |
| "Congratulations! You won ₹25 lakh in KBC lucky draw. Pay processing fee ₹12,500 to claim." | prize 15, fee + payment (capped 30), advance-fee combo 20 | **65, MALICIOUS** |
| "You received ₹5000 cashback. Enter UPI PIN to receive the amount." | prize 15, UPI PIN 30, combo 20 | **65, MALICIOUS** |
| "Your Amazon account is locked. Call customer care and install AnyDesk to verify." | threat 15, bank/support refs 10, remote access 25, combo 20 | **70, MALICIOUS** |
| "Join our VIP Telegram group. Guaranteed 30% daily returns on crypto!" | returns 20 + topic 5, off-platform 5, combo 15 | **45, SUSPICIOUS** |

---

## 4. Text preprocessing pipeline

The **display text** (returned to the user) is kept exactly as submitted, minus control
characters. The **detection text** below is only used internally.

1. **Validate:** 1–5000 characters (schema). Reject if nothing remains after stripping whitespace.
2. **Remove invisible characters:** zero-width (U+200B–U+200D, U+2060, U+FEFF) and bidirectional
   controls (U+202A–U+202E, U+2066–U+2069). Count them; if any were present →
   `MSG_HIDDEN_CHARACTERS`.
3. **Unicode NFKC normalisation:** full-width / stylised letters (𝐎𝐓𝐏, ＯＴＰ) → plain ASCII.
4. **Extract links first**, before other folding changes them:
   - `http(s)://…`, `www.…`, and bare domains with a known public suffix (`sbi-kyc.xyz/login`),
     using the bundled Public Suffix List;
   - de-obfuscation: `hxxp`, `[.]`, `(dot)`, `[dot]`, `" . "` between domain labels.
   Each link is replaced by a placeholder token, so its words are not counted twice (the URL module
   analyses them). At most 5 links are analysed; extra ones are listed as "not analysed".
5. **Extract entities:** Indian mobile numbers (`+91`/`0` prefixes, 10 digits starting 6–9),
   toll-free/landline numbers, e-mail addresses, UPI IDs (`name@handle`), and amounts (`₹`, `Rs`,
   `INR`, `rupees`, lakh/crore).
6. **Homoglyph folding** (reusing `url_rules.yaml`): Cyrillic/Greek look-alikes → Latin.
7. **Lowercase** and **leetspeak folding** only inside tokens that mix letters and digits
   (`0TP` → `otp`, `p@ssw0rd` → `password`), so real numbers such as "OTP 482913" stay unchanged.
8. **Collapse** repeated letters (3+ → 2: `urgenttt` → `urgentt`, `freeee` → `free`) and whitespace.
9. **Split into sentences** (`. ! ?` and newlines). This is used for negation scope and to report
   where a phrase was found.
10. **Language check:** if more than 30 % of the letters are not Latin (e.g. Devanagari), add the
    info indicator `MSG_LANGUAGE_NOT_SUPPORTED` and set confidence to LOW. Hindi/Marathi rules are
    future scope.

**Safety:** every pattern uses bounded windows (`(?:\W+\w+){0,4}`) and no nested quantifiers.
Patterns are compiled once at startup. A test checks that a 5000-character adversarial input is
processed in under 200 ms (ReDoS protection).

---

## 5. API contract

`POST /api/analyze/message`

```json
{ "text": "Dear customer, your SBI account will be BLOCKED today. Update KYC immediately: http://sbi-kyc-update.xyz/login",
  "save_to_history": false }
```

| Status | When |
|---|---|
| 200 | Analysis result (same shape as `/api/analyze/url`: `risk_score`, `risk_level`, `confidence`, `verification`, `summary`, `categories`, `indicators`, `recommendation`, `score_breakdown`, `threat_intel`, `analysis`, `disclaimer`, `engine_version`) |
| 400 `VALIDATION_ERROR` | Missing, empty, > 5000 characters, wrong type, unknown field |
| 413 / 415 / 429 | As for all endpoints |
| 422 `TEXT_NOT_ANALYZABLE` | Fewer than 3 letters after preprocessing (e.g. only emojis or numbers) |

`analysis` for messages:

```json
{
  "text_length": 118,
  "language": { "script": "latin", "supported": true },
  "preprocessing": { "hidden_characters_removed": 0, "links_found": 1, "links_deobfuscated": 0 },
  "matched_phrases": [
    { "indicator": "MSG_ACCOUNT_THREAT", "phrase": "account will be BLOCKED", "sentence": 1 },
    { "indicator": "MSG_URGENCY", "phrase": "immediately", "sentence": 2 }
  ],
  "links": [
    { "url": "http://sbi-kyc-update.xyz/login", "risk_score": 58, "risk_level": "SUSPICIOUS",
      "indicator_ids": ["BRAND_IN_DOMAIN_NAME", "URL_SUSPICIOUS_TLD", "URL_NO_HTTPS", "URL_PHISHING_KEYWORD"] }
  ],
  "entities": { "phone_numbers": [], "emails": [], "upi_ids": [], "amounts": [] }
}
```

- `indicators` combines message indicators with the indicators of the **riskiest link**. Their
  evidence is prefixed with the link's domain.
- `score_breakdown` additionally shows `primary_score` and `rule_used`
  (`primary` or `weighted_with_links`).
- **Privacy:** the text is never logged or stored. History (later) stores only the score, level,
  indicator IDs, message length and link count, never the text or entities.

---

## 6. Test cases

**Preprocessing (unit)**
- NFKC (`ＯＴＰ` → otp), zero-width removal counts, bidi-control removal
- Link extraction: `http(s)`, `www.`, bare domain, `hxxps://evil[.]xyz`, `evil(dot)com`,
  trailing punctuation (`…/login.` and `(http://x.com)`), more than 5 links
- Entities: `+91 98765 43210`, `09876543210`, `1800-123-4567`, `abc@okaxis`, `₹1,999`,
  `Rs.499`, `25 lakh`
- Leetspeak only in mixed tokens (`0TP` → otp; "OTP 482913" unchanged); repeated letters; sentences

**Rules (unit, one positive and one negative per indicator)**
- Each of the ~28 indicators fires on its example and does **not** fire on a near-miss
  (e.g. "OTP" alone ≠ `MSG_OTP_REQUEST`; "won the match" ≠ `MSG_PRIZE_REWARD`)
- Negation: "never share your OTP", "do not share this code", "bank will never ask for your PIN"
  → `MSG_SECURITY_ADVICE`, no request indicator
- Negation scope: "Do not delay. Share the OTP now." → the request still fires (different sentence)
- Combinations fire only when every group matches
- **Property test:** every single-indicator example scores < 60, and only request-type indicators
  reach ≥ 30
- ReDoS: 5000 characters of `share share share …` / `!!!!…` finish in < 200 ms

**Scoring (unit)**
- Multi-label categories (fake KYC → kyc_account_suspension + impersonation + phishing +
  malicious_url)
- Fallback `social_engineering_other`
- No-dilution rule: scam text + clean link keeps the text score; mild text + bad link raises it
- Link floors propagate (look-alike link → ≥ 60), a threat-intel listing → 90 + VERIFIED
  (threat_intelligence)
- A trusted link in a message does not VERIFY the message

**API (integration, network faked)**
- 200 shape and all fields; 400 empty / whitespace / 5001 characters / wrong type / unknown field;
  422 emoji-only
- Links analysed through the URL service with fake DNS/HTTP, and a shortener in a message followed
  safely
- The message text never appears in logs (checked with `caplog`)

**Labelled demo set (`demo-data/messages.yaml`, all marked DEMO / TEST DATA, no real personal
data)**
- About 40 messages: genuine OTP, genuine debit/credit alerts, genuine interview invite, genuine
  delivery update, and one scam for each of the 13 specific categories, with expected level and
  categories
- One test runs the whole set and reports accuracy; the Week 8 tuning target is 0 genuine messages
  scored MALICIOUS
