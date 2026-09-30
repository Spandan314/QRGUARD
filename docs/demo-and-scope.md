# Expected Final Demonstration and Scope Boundaries

## 1. Expected final demonstration (≈ 12 minutes)

> The step-by-step script with verified expected results is [demo-runbook.md](demo-runbook.md).

All inputs come from `demo-data/`, labelled **DEMO / TEST DATA**. No real people's data is used and no
live phishing pages are shown.

| # | Scenario | Input | Expected outcome |
|---|---|---|---|
| 1 | Harmless QR | QR → `https://www.wikipedia.org` | ✅ SAFE, few or no indicators, TI "not listed", **link not opened automatically**, confirm dialog on "Open" |
| 2 | Suspicious QR | QR → `http://bit.ly/…` shortener resolving to a `.example` lookalike login | ⚠️ SUSPICIOUS/⛔ MALICIOUS: shortener, redirect chain, lookalike brand, HTTP |
| 3 | UPI "receive money" QR | QR with `upi://pay?pa=…&am=5000` + message "scan to receive your refund" | ⛔: explains that scanning a UPI QR only ever **sends** money |
| 4 | Known-malicious URL | A Google Safe Browsing **test URL** and a `demo_blocklist` `.example` entry | ⛔ MALICIOUS with TI `listed`, confidence HIGH |
| 5 | TI unavailable | Disable network to a provider (env flag) | Result still returned. Provider shown as "unavailable", confidence lowered. |
| 6 | Genuine bank SMS | "…Never share your OTP with anyone…" transaction alert | ✅ SAFE: shows the warning phrase was recognised as legitimate |
| 7 | Fake KYC SMS | Threat + urgency + lookalike link | ⛔ with combination-bonus explanation |
| 8 | Fake internship | "Registration fee ₹1999, no interview, contact on Telegram" | ⚠️/⛔: job + fee combination |
| 9 | Screenshot | Synthetic screenshot of a lottery scam | Extracted text, detected URL, highlighted phrases, combined score |
| 10 | QR generator | Generate a Wi-Fi QR on the phone, save, share | Works offline. Clearly separate from the detection workflow. |
| 11 | History & privacy | Show history (no message text stored), delete one, delete all | Firestore console shows only metadata |
| 12 | Security | Postman: SSRF attempt `http://169.254.169.254`, 20 MB upload, `.exe` renamed `.png`, rate-limit burst | Blocked, 413, 415, 429, with clean JSON errors |
| 13 | Results | Evaluation table: precision/recall per input type on our labelled set | Honest numbers, including known failures |

## 2. Out of scope for the 3-month MVP (agreed; documented as future scope)

The following are **not implemented** in the initial version:

| Item | Why it is excluded / future direction |
|---|---|
| Deep learning model training | Needs data, GPUs and evaluation time. The indicator vector is ML-ready. |
| Large-scale custom dataset creation | We build only a small labelled evaluation set (about 150 items). |
| Transformer-based NLP | Rule-based detection is explainable and sufficient for the MVP. |
| Continuous background monitoring | Battery, permissions and platform policy constraints |
| Browser extension | A separate platform, and future scope |
| Real-time device-wide protection | Needs OS-level integration |
| Automatic blocking of websites | QRGUARD advises and never blocks |
| Automatic deletion / quarantine of files | Not an antivirus, and it never touches user files |
| Full antivirus functionality | Out of the project's objective |
| Production-scale threat-intelligence infrastructure | We use existing feeds/APIs with a cache |
| Complex admin management system | The admin view is limited to stats and a reports list |
| Multilingual AI model | English rules only. Hindi/Marathi rules are future scope. |
| Federated learning | Research topic |
| Blockchain | Adds nothing to the objective |
| Advanced user reporting / reputation network | Only a simple "report false result" form |

Also not planned: iOS App Store release (needs a paid Apple account), fetching or rendering page
content, and any claim of guaranteed or "100 %" detection.
