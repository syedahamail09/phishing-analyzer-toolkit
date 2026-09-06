"""
Phishing Awareness Analyzer
===========================
DecodeLabs Cyber Security Industrial Training Kit (Batch 2026) — Project 3

A dependency-free Python tool that performs non-expert triage on suspicious
emails/messages. It parses a simple plain-text email format, scans for the
red flags described below, and outputs a verdict (Safe / Suspicious /
Malicious) along with the recommended action (Close / Warn User /
Block & Escalate).

Author: Syeda Hamail
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Reference data (kept simple and editable — no external dependencies)
# ---------------------------------------------------------------------------

# Brands most commonly impersonated in phishing/typosquatting campaigns.
KNOWN_BRANDS = [
    "google", "microsoft", "paypal", "amazon", "apple", "facebook",
    "netflix", "linkedin", "bankofamerica", "chase", "wellsfargo",
    "dropbox", "instagram", "twitter", "outlook", "office365",
]

# Known URL shortener domains (common vector for hiding a real destination).
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly",
}

# File extensions that should never legitimately arrive as an email
# attachment in a normal business context.
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar",
    ".iso", ".lnk", ".ps1", ".hta", ".msi", ".wsf",
}

# Cognitive-trigger keyword banks (Authority / Urgency / Curiosity / Fear-Greed)
URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "within 24 hours", "expires today",
    "final notice", "account locked", "account will be suspended",
    "immediate action required", "time-sensitive", "right away",
    "mandatory", "strict deadline", "failure to complete",
]

# Phrases that neutralize an urgency/authority hit if present right around it
# (keeps the tool from flagging deliberately non-urgent, low-pressure emails).
NEGATION_PHRASES = [
    "non-urgent", "not urgent", "no immediate action", "no urgency",
]
AUTHORITY_KEYWORDS = [
    "ceo", "law enforcement", "irs", "government", "legal action",
    "compliance department", "executive order", "strictly confidential",
    "bypass standard procedure", "do not discuss with anyone",
]
FEAR_GREED_KEYWORDS = [
    "you have won", "claim your prize", "lawsuit", "suspended",
    "unauthorized access", "unusual activity", "verify your account",
    "confirm your identity", "free gift", "reward", "lottery",
]
SENSITIVE_INFO_REQUESTS = [
    "password", "one-time code", "otp", "social security", "ssn",
    "card number", "cvv", "pin number", "wire transfer",
    "banking details", "login credentials", "mfa code", "verification code",
]

GENERIC_GREETINGS = ["dear customer", "dear user", "dear valued customer", "dear member"]

# Public email providers — a "CEO"/"IT"/"HR" sender using one of these is a
# strong Display-Name-Spoofing signal.
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "protonmail.com", "icloud.com",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class RedFlag:
    category: str
    detail: str
    weight: int  # contribution to the risk score


@dataclass
class ParsedMessage:
    display_name: str = ""
    sender_email: str = ""
    subject: str = ""
    body: str = ""
    links: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    raw: str = ""


@dataclass
class TriageResult:
    verdict: str          # "Safe" | "Suspicious" | "Malicious"
    action: str            # "Close" | "Warn User" | "Block & Escalate"
    score: int
    flags: list[RedFlag]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

FROM_RE = re.compile(r"^From:\s*(.*)$", re.IGNORECASE | re.MULTILINE)
SUBJECT_RE = re.compile(r"^Subject:\s*(.*)$", re.IGNORECASE | re.MULTILINE)
ATTACHMENT_RE = re.compile(r"^Attachment:\s*(.*)$", re.IGNORECASE | re.MULTILINE)
EMAIL_IN_BRACKETS_RE = re.compile(r"<([^<>]+)>")
URL_RE = re.compile(r"https?://[^\s)>\]\"']+")


def parse_message(raw_text: str) -> ParsedMessage:
    """Parse a simple plain-text email dump into structured fields.

    Expected (loose) format:
        From: Display Name <email@domain.com>
        Subject: ...
        Attachment: filename.ext        (optional, one per line, repeatable)

        <blank line>
        body text, including any http(s):// links inline
    """
    msg = ParsedMessage(raw=raw_text)

    from_match = FROM_RE.search(raw_text)
    if from_match:
        from_line = from_match.group(1).strip()
        email_match = EMAIL_IN_BRACKETS_RE.search(from_line)
        if email_match:
            msg.sender_email = email_match.group(1).strip().lower()
            msg.display_name = from_line[: email_match.start()].strip().strip('"')
        else:
            # No angle brackets — treat the whole thing as either name or email
            if "@" in from_line:
                msg.sender_email = from_line.lower()
            else:
                msg.display_name = from_line

    subject_match = SUBJECT_RE.search(raw_text)
    if subject_match:
        msg.subject = subject_match.group(1).strip()

    msg.attachments = [a.strip() for a in ATTACHMENT_RE.findall(raw_text)]

    # Body = everything after the first blank line (falls back to full text)
    parts = raw_text.split("\n\n", 1)
    msg.body = parts[1] if len(parts) > 1 else raw_text

    msg.links = URL_RE.findall(raw_text)

    return msg


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _domain_of(email: str) -> str:
    return email.split("@")[-1].lower() if "@" in email else ""


def _levenshtein(a: str, b: str) -> int:
    """Small dependency-free edit-distance implementation for typosquat checks."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def _root_domain(netloc: str) -> str:
    """Best-effort extraction of the registrable root (last two labels)."""
    labels = netloc.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return netloc


def _check_sender_domain_mismatch(msg: ParsedMessage) -> list[RedFlag]:
    flags: list[RedFlag] = []
    name_lower = msg.display_name.lower()
    domain = _domain_of(msg.sender_email)

    # Does the display name claim to be a brand or role that the domain
    # doesn't match (e.g. "Microsoft Support" from a gmail.com address)?
    for brand in KNOWN_BRANDS:
        if brand in name_lower and brand not in domain:
            flags.append(RedFlag(
                "Sender-Domain Mismatch",
                f'Display name references "{brand.title()}" but the sending '
                f'domain is "{domain}", which does not belong to {brand.title()}.',
                weight=3,
            ))
            break

    if domain in FREE_EMAIL_DOMAINS and any(
        role in name_lower for role in
        ["ceo", "support", "it security", "hr", "human resources", "admin", "director"]
    ):
        flags.append(RedFlag(
            "Sender-Domain Mismatch",
            f'Sender claims an official/executive role ("{msg.display_name}") '
            f'but is sending from a free public email provider ({domain}).',
            weight=3,
        ))

    return flags


def _check_lookalike_domain(domain: str) -> list[RedFlag]:
    flags: list[RedFlag] = []
    if not domain:
        return flags
    root = _root_domain(domain)
    for brand in KNOWN_BRANDS:
        brand_domain = f"{brand}.com"
        if root == brand_domain:
            continue  # exact legitimate match, not a lookalike
        dist = _levenshtein(root, brand_domain)
        if 0 < dist <= 2:
            flags.append(RedFlag(
                "Lookalike / Typosquatted Domain",
                f'Domain "{domain}" closely resembles "{brand_domain}" '
                f'(edit distance {dist}) — likely typosquatting.',
                weight=4,
            ))
    # Combosquatting: brand name + security-sounding words on a domain that
    # is NOT the brand's real root domain.
    if any(word in domain for word in ["secure", "login", "verify", "update", "account"]) and \
       any(brand in domain for brand in KNOWN_BRANDS) and \
       not any(domain.endswith(f"{brand}.com") for brand in KNOWN_BRANDS):
        flags.append(RedFlag(
            "Combosquatting",
            f'Domain "{domain}" pairs a brand name with a security-related '
            f'word — a common combosquatting pattern.',
            weight=3,
        ))
    return flags


def _check_links(msg: ParsedMessage) -> list[RedFlag]:
    flags: list[RedFlag] = []
    seen_shorteners = set()
    seen_lookalikes = set()

    for link in msg.links:
        try:
            parsed = urlparse(link)
        except ValueError:
            continue
        netloc = parsed.netloc.lower()

        if netloc in URL_SHORTENERS and netloc not in seen_shorteners:
            seen_shorteners.add(netloc)
            flags.append(RedFlag(
                "Suspicious Link",
                f'Link uses a URL shortener ("{netloc}") which hides the '
                f'true destination: {link}',
                weight=2,
            ))

        # Raw IP address as host — never legitimate for a corporate login page.
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", netloc):
            flags.append(RedFlag(
                "Suspicious Link",
                f'Link points directly to an IP address rather than a '
                f'domain name: {link}',
                weight=4,
            ))

        # Long/nested subdomain trap, e.g. company.tech.login-update.com
        if netloc.count(".") >= 3 and netloc not in seen_lookalikes:
            seen_lookalikes.add(netloc)
            flags.append(RedFlag(
                "Suspicious Link",
                f'Link uses a deeply nested subdomain that may bury the '
                f'true root domain (read right-to-left to check): {netloc}',
                weight=3,
            ))

        flags.extend(f for f in _check_lookalike_domain(netloc) if f.detail not in
                      {existing.detail for existing in flags})

    return flags


def _check_attachments(msg: ParsedMessage) -> list[RedFlag]:
    flags: list[RedFlag] = []
    for attachment in msg.attachments:
        suffix = Path(attachment).suffix.lower()
        if suffix in DANGEROUS_EXTENSIONS:
            flags.append(RedFlag(
                "Dangerous Attachment",
                f'Attachment "{attachment}" has a high-risk extension '
                f'("{suffix}") rarely used for legitimate business documents.',
                weight=4,
            ))
    return flags


def _strip_negations(text: str) -> str:
    """Remove known negation phrases so they can't trigger a false-positive
    keyword hit (e.g. "non-urgent" should not count as "urgent")."""
    cleaned = text
    for phrase in NEGATION_PHRASES:
        cleaned = cleaned.replace(phrase, "")
    return cleaned


def _check_keyword_bank(text: str, bank: list[str], category: str, weight: int) -> list[RedFlag]:
    flags: list[RedFlag] = []
    lower = _strip_negations(text.lower())
    hits = [kw for kw in bank if kw in lower]
    if hits:
        flags.append(RedFlag(
            category,
            f'Message contains {category.lower()} language: '
            f'{", ".join(sorted(set(hits))[:4])}.',
            weight=weight,
        ))
    return flags


def _check_generic_greeting(text: str) -> list[RedFlag]:
    lower = text.lower()
    if any(greet in lower for greet in GENERIC_GREETINGS):
        return [RedFlag(
            "Generic Greeting",
            "Message uses an impersonal greeting instead of the recipient's "
            "name — common in mass-phishing templates.",
            weight=1,
        )]
    return []


# ---------------------------------------------------------------------------
# Core triage engine
# ---------------------------------------------------------------------------

def analyze(msg: ParsedMessage) -> TriageResult:
    full_text = f"{msg.subject}\n{msg.body}"

    flags: list[RedFlag] = []
    flags += _check_sender_domain_mismatch(msg)
    flags += _check_lookalike_domain(_domain_of(msg.sender_email))
    flags += _check_links(msg)
    flags += _check_attachments(msg)
    flags += _check_keyword_bank(full_text, URGENCY_KEYWORDS, "Urgency", weight=2)
    flags += _check_keyword_bank(full_text, AUTHORITY_KEYWORDS, "Authority", weight=2)
    flags += _check_keyword_bank(full_text, FEAR_GREED_KEYWORDS, "Fear/Greed", weight=2)
    flags += _check_keyword_bank(full_text, SENSITIVE_INFO_REQUESTS, "Sensitive Info Request", weight=3)
    flags += _check_generic_greeting(full_text)

    score = sum(f.weight for f in flags)

    if score >= 8:
        verdict, action = "Malicious", "Block & Escalate"
    elif score >= 3:
        verdict, action = "Suspicious", "Warn User"
    else:
        verdict, action = "Safe", "Close"

    return TriageResult(verdict=verdict, action=action, score=score, flags=flags)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def format_report(msg: ParsedMessage, result: TriageResult, source_name: str = "") -> str:
    lines = []
    header = f"Phishing Triage Report — {source_name}" if source_name else "Phishing Triage Report"
    lines.append(header)
    lines.append("=" * len(header))
    lines.append(f"From:    {msg.display_name} <{msg.sender_email}>" if msg.display_name else f"From:    {msg.sender_email}")
    lines.append(f"Subject: {msg.subject}")
    lines.append("")
    lines.append(f"Risk Score: {result.score}")
    lines.append(f"Verdict:    {result.verdict}")
    lines.append(f"Action:     {result.action}")
    lines.append("")

    if result.flags:
        lines.append(f"Red Flags Found ({len(result.flags)}):")
        for i, flag in enumerate(result.flags, 1):
            lines.append(f"  {i}. [{flag.category}] {flag.detail}")
    else:
        lines.append("No red flags detected.")

    lines.append("")
    lines.append("Why this matters: " + explain_why_unsafe(result))
    return "\n".join(lines)


def explain_why_unsafe(result: TriageResult) -> str:
    if result.verdict == "Malicious":
        return ("Multiple high-confidence indicators (spoofed sender, deceptive "
                "links/attachments, and psychological pressure tactics) combine "
                "to make this a near-certain phishing attempt. Do not click, "
                "reply, or open attachments — report and block immediately.")
    if result.verdict == "Suspicious":
        return ("Some indicators are present but not conclusive. Treat with "
                "caution: verify the sender through a separate, known channel "
                "(e.g. call a listed phone number) before acting on any request "
                "in this message.")
    return ("No significant phishing indicators were detected. Standard "
            "vigilance still applies — if anything about the message feels "
            "off, verify independently before acting.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a plain-text email/message for phishing red flags."
    )
    parser.add_argument(
        "path",
        help="Path to a single message file, or a directory of message files.",
    )
    args = parser.parse_args(argv)

    target = Path(args.path)
    if not target.exists():
        print(f"Error: path not found: {target}", file=sys.stderr)
        return 1

    files = sorted(target.glob("*.txt")) if target.is_dir() else [target]
    if not files:
        print(f"No .txt message files found in {target}", file=sys.stderr)
        return 1

    for i, file_path in enumerate(files):
        raw = file_path.read_text(encoding="utf-8", errors="replace")
        msg = parse_message(raw)
        result = analyze(msg)
        print(format_report(msg, result, source_name=file_path.name))
        if i != len(files) - 1:
            print("\n" + "-" * 60 + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
