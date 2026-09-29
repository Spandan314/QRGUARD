# Expected Final Demonstration and Scope Boundaries

## 1. Expected final demonstration (≈ 12 minutes)

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

## 2. Out of scope for the 3-month MVP (do NOT implement)

| Item | Reason |
|---|---|
| ML / transformer-based classifiers | Needs data, training and evaluation time. The indicator vector is kept ML-ready instead. |
| Browser extension | A separate platform with its own review process |
| Android share-sheet / SMS-reading integration | Needs native code and a dev build, and SMS permissions raise Play Store policy issues |
| Multilingual (Hindi/Marathi) detection | Needs native-speaker rule sets and OCR language packs. Only a feasibility note in Week 10. |
| Fetching / rendering page content, screenshots of websites, sandbox detonation | Security risk (SSRF, malware) and heavy infrastructure |
| Our own crawling / threat feed / campaign clustering | Research-scale work |
| Real-time push alerts, background scanning | Battery, permissions and complexity |
| iOS App Store release | Needs a paid Apple developer account. Expo Go iOS testing is possible if a team member has an iPhone. |
| Federated / privacy-preserving learning | Research topic |
| Payments, multi-tenant orgs, complex admin RBAC | Not needed for the objective |
| Claims of guaranteed or "100 %" detection | Not truthful |
