# Phishing Triage Toolkit

**DecodeLabs Cyber Security Industrial Training Kit (Batch 2026) — Project 3: Phishing Awareness Analysis**

A dependency-free Python tool that plays the role of a Cybersecurity Analyst's
first line of defense: it takes a plain-text email/message, scans it against a
set of known phishing red flags, and returns a triage verdict with a clear,
actionable outcome — no security expertise required to read the report.

## Why this exists

80% of security breaches involve phishing, and it takes an attacker roughly
82 seconds on average to get their first click. Technical firewalls can't
compensate for human error — the real perimeter is the user. This tool builds
the "Pause, Verify, Report" habit into a repeatable, automated first pass.

## Features

Detects red flags across four categories:

| Category | Examples caught |
|---|---|
| **Sender & Domain** | Display-name spoofing (e.g. "Microsoft Support" from a Gmail address), lookalike/typosquatted domains, combosquatting |
| **Links** | URL shorteners, raw IP addresses as the link host, deeply nested subdomains that bury the true root domain |
| **Attachments** | High-risk file extensions (`.exe`, `.scr`, `.js`, `.iso`, `.lnk`, etc.) |
| **Psychology** | Urgency, authority, fear/greed language, generic greetings, requests for sensitive info (passwords, OTPs, wire transfers) |

Each detected flag adds to a risk score, which maps to a verdict and a
required action:

```
Incoming Message
       │
       ▼
 ┌───────────┐     score < 3      ┌────────┐
 │  Analyze  ├───────────────────►│  Safe  ├──► Close
 └───────────┘                    └────────┘
       │ 3 ≤ score < 8
       ▼
 ┌─────────────┐
 │ Suspicious  ├──► Warn User
 └─────────────┘
       │ score ≥ 8
       ▼
 ┌────────────┐
 │ Malicious  ├──► Block & Escalate
 └────────────┘
```

## Usage

Analyze a single message:

```bash
python phishing_analyzer.py samples/sample_1_bec_wire_transfer.txt
```

Analyze every `.txt` message in a folder:

```bash
python phishing_analyzer.py samples/
```

### Message format

The analyzer expects a simple plain-text dump of the message:

```
From: Display Name <email@domain.com>
Subject: Subject line here
Attachment: filename.ext        (optional, repeatable)

Body text goes here, including any http(s):// links inline.
```

### Example output

```
Phishing Triage Report — sample_2_credential_harvest.txt
========================================================
From:    Microsoft Support <support@logins-updates.com>
Subject: FW: Urgent Your Account Security Alert

Risk Score: 14
Verdict:    Malicious
Action:     Block & Escalate

Red Flags Found (6):
  1. [Sender-Domain Mismatch] Display name references "Microsoft" but the
     sending domain is "logins-updates.com", which does not belong to Microsoft.
  2. [Suspicious Link] Link uses a deeply nested subdomain that may bury the
     true root domain (read right-to-left to check): www.decodelabs.tech.login-update.com
  3. [Urgency] Message contains urgency language: act now, immediately, urgent, within 24 hours.
  4. [Fear/Greed] Message contains fear/greed language: confirm your identity, suspended, unusual activity.
  5. [Sensitive Info Request] Message contains sensitive info request language: password.
  6. [Generic Greeting] Message uses an impersonal greeting instead of the recipient's name.

Why this matters: Multiple high-confidence indicators combine to make this
a near-certain phishing attempt. Do not click, reply, or open attachments —
report and block immediately.
```

## Non-Expert Triage Checklist

A quick manual reference for anyone auditing an inbox without this tool:

- [ ] **Check the sender's actual domain**, not just the display name
- [ ] **Hover over links** before clicking — does the visible text match the real destination?
- [ ] **Read the URL right-to-left** to find the true root domain (e.g. `company.tech.login-update.com` is really a `login-update.com` link)
- [ ] **Be wary of URL shorteners** (bit.ly, tinyurl, etc.) — they hide the destination
- [ ] **Never trust unsolicited urgency** — "act now," "account locked," "24 hours" are pressure tactics
- [ ] **Question authority claims** — a real CEO or IT department rarely demands secrecy or a bypassed process
- [ ] **Flag dangerous attachments** — `.exe`, `.scr`, `.js`, `.iso`, `.lnk` should never arrive as normal business documents
- [ ] **Never provide passwords, OTPs, or wire details over email** — verify through a separate, known channel
- [ ] **When in doubt: Pause → Verify (via a known phone number/contact) → Report**

## Key Concepts Covered

- **Phishing hierarchy**: Mass phishing → Spear phishing → Whaling
- **Multi-channel vectors**: Smishing (SMS), Vishing (voice), Quishing (QR codes), search-engine phishing
- **Domain deception**: Typosquatting, homoglyph attacks, combosquatting, subdomain traps, dangling DNS takeover
- **Cognitive triggers**: Authority, Urgency, Curiosity, Fear/Greed
- **The golden rule**: Pause, Verify, Report

## Project Structure

```
phishing-triage-toolkit/
├── phishing_analyzer.py   # Core detection engine + CLI
├── samples/                # Example messages (malicious, suspicious, safe)
│   ├── sample_1_bec_wire_transfer.txt
│   ├── sample_2_credential_harvest.txt
│   ├── sample_3_suspicious_shortlink.txt
│   └── sample_4_legitimate.txt
└── README.md
```

## Requirements

Python 3.9+. No external dependencies — standard library only.

---

**Author:** Syeda Hamail
**Program:** DecodeLabs Cyber Security Industrial Training Kit, Batch 2026
