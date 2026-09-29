# Research Basis and Academic Contribution

## 1. Reference paper

**Title:** *QsecR: Secure QR Code Scanner According to a Novel Malicious URL Detection Framework*
**Link:** https://ieeexplore.ieee.org/document/10172018 (listed under IEEE Journals & Magazines)

### 1.1 Access status (read this first)

The full text **could not be accessed** while this document was written. The IEEE Xplore site and the
scholarly metadata APIs were blocked from the build environment. Everything below comes from the
**publicly indexed abstract only**, as it appears in search results from IEEE Xplore and ResearchGate.
We have not guessed or filled in any detail that is not in the abstract.

**Team action (Week 1):** download the full text through the college's IEEE subscription and complete
the "To verify from full text" column in 1.3. Do not cite any detail in the final report until someone
has confirmed it in the PDF.

### 1.2 What the abstract states

| Aspect | From the abstract |
|---|---|
| Problem addressed | QR codes that carry malicious URLs are an open security issue. Existing secure QR scanner apps mostly rely on **blacklists**, which fail against newly created malicious sites. |
| Criticism of pure ML | ML-based URL detection depends on the data and needs large, up-to-date training sets. |
| Proposed system | **QsecR**, an Android QR code scanner built on a new malicious-URL detection framework. It aims to be secure and privacy-friendly. |
| Features | A predefined static-feature classification with **39 features** in four classes: **blacklist, lexical, host-based and content-based**. |
| Dataset | **4,000 real-world URLs** collected from **URLhaus** and **PhishTank**. |
| Results | **93.50 % detection accuracy**, **93.80 % precision**. The authors report this as higher than existing secure QR scanners. |
| Privacy claim | They describe it as the most privacy-friendly of the compared apps, using the fewest permissions. |

### 1.3 Analysis template (complete from full text)

| Item | Our reading so far | To verify from full text |
|---|---|---|
| Methodology | Feature-based classification of the decoded URL | Is it rule-based, weighted, or a trained classifier? How are the 39 features combined? |
| Dataset/inputs | URLs only (decoded from QR codes) | Class balance, benign-URL source, date of collection |
| Features | Blacklist, lexical, host-based, content-based | Full list of 39 features; does content-based mean fetching the page? |
| Detection approach | Static features | Thresholds, weights, any online lookups |
| Results | 93.50 % accuracy, 93.80 % precision | Recall, F1, false-positive rate, comparison baseline apps |
| Limitations | Not stated in the abstract | Authors' own limitations section |

### 1.4 Research gap QRGUARD addresses (based only on the verified scope above)

1. **Input scope.** QsecR analyses URLs decoded from QR codes. Real scams also arrive as SMS/WhatsApp
   text, as screenshots, and as non-URL QR payloads such as **UPI payment intents**, which are central
   to QR fraud in India. QRGUARD analyses all of these inside one framework.
2. **Explainability to end users.** The abstract reports classification accuracy. It does not describe
   explaining each verdict to a non-technical user. QRGUARD returns every contributing indicator with
   a plain-language reason and a recommended action.
3. **Regional scam patterns.** QRGUARD's message rules target India-specific scam scripts: KYC, UPI
   "receive money" QR tricks, fake internships and task-based job scams.
4. **Transparent degradation.** QRGUARD reports whether each threat-intelligence source was checked,
   unavailable or disabled. It never treats "not on a blacklist" as "safe".

### 1.5 How QRGUARD differs from QsecR

| | QsecR (from abstract) | QRGUARD |
|---|---|---|
| Platform | Android app | Android app (Expo), web app, REST API |
| Inputs | QR → URL | QR (camera/image), URL, message text, screenshot (OCR) |
| Detector | 39 static features, blacklist + lexical + host + content | Explainable weighted rules across URL, QR-payload, message and OCR modules, plus threat intelligence |
| Content-based features | Included | **Deliberately limited.** We do not download page bodies (SSRF, privacy and malware risk). Only redirect headers are read, under strict SSRF controls. |
| Output | Classification | Score 0–100, level, confidence, indicators, reasons, recommended action |
| Accuracy claim | 93.5 % on 4,000 URLs | **No accuracy claim** until we evaluate on our own labelled test set (see Testing). Results are not directly comparable with QsecR because the datasets differ. |

We adopt QsecR's **four-class feature taxonomy** (blacklist / lexical / host / content) to organise our
URL indicators, and we cite it. That is a reuse of their categorisation, not of their implementation.

## 2. Research contribution (honest framing)

### Proposed contribution statement

> An explainable, multi-input security analysis framework that normalises evidence from QR decoding,
> URL structural analysis, rule-based scam-message detection, OCR-based screenshot analysis and
> threat-intelligence lookups into a **single indicator schema**. A configurable, weighted and
> **evidence-combining** risk model then produces a user-facing verdict, reasons and a safe action.

### What is genuinely ours (defensible as contribution)

1. **Unified indicator schema.** Every module emits the same `Indicator` structure (id, category,
   weight, evidence, plain-language explanation). This makes URL, message, QR and OCR evidence
   comparable and combinable.
2. **Evidence-combination scoring model.** The strongest module sets the base score, and independent
   corroborating evidence adds a damped bonus. Rule combinations (for example, credential request plus
   impersonation) score higher than isolated keywords. Threat-intelligence hits act as a floor. Every
   point in the score can be traced to an indicator.
3. **QR payload semantics beyond URLs.** Rules for UPI payment intents, such as the "you only ever
   *pay* by scanning" warning, prefilled amounts and payee mismatch, and for APK download links and
   Wi-Fi payloads.
4. **Negation-aware scam rules.** The rules tell a genuine bank warning ("Never share your OTP") apart
   from a request to share an OTP, which reduces false positives on real bank SMS.
5. **Privacy-preserving history design.** No raw messages, screenshots or full URLs are stored by
   default. Only the verdict metadata is kept.
6. **A small labelled evaluation set** of India-context scam and genuine messages, URLs and QR codes,
   with honestly reported precision and recall.

### What is integration of existing technology (do not claim as novel)

Tesseract OCR, OpenCV QR decoding, the URLhaus / Google Safe Browsing / VirusTotal APIs, Firebase,
Expo and Flask. The individual URL features (IP host, `@`, punycode, TLD lists) are well known in the
phishing-detection literature.

### Claims to avoid

- "Detects all scams" / "100 % accurate" / "better than QsecR" (not measured on the same data).
- "AI-powered". The MVP is rule-based, so describe it that way.

## 3. Further literature to survey (Week 1, verify each yourselves)

Search IEEE Xplore / Google Scholar for: QR phishing ("quishing") surveys, lexical URL phishing
features, SMS spam/scam detection (e.g. the UCI SMS Spam Collection dataset), homograph/IDN attacks, and
OCR-based phishing detection. Record each paper in `docs/literature-survey.md` with the same template as
section 1.3. Only include papers someone on the team has actually read.
