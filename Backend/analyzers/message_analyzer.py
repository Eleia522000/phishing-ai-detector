"""Message wording and social-engineering analysis."""

from Backend.config import SUSPICIOUS_MESSAGE_WORDS
from Backend.utils.helpers import dedupe_keep_order


def contains_high_risk_phishing_language(text: str) -> bool:
    """Return True when the text contains strong phishing language."""
    text_lower = (text or "").lower()

    high_risk_patterns = [
        "urgent", "suspended", "account suspended", "account locked", "locked",
        "limited", "restricted", "verify immediately", "verify your account",
        "verify your password", "confirm your account", "confirm your details",
        "confirm your information", "confirm your identity", "update your information",
        "update your account", "billing details", "password", "credentials",
        "account closure", "will be deleted", "failure to comply", "claim your prize",
        "free iphone", "gift card", "bank account", "security alert", "login now",
        "act now",
    ]

    return any(pattern in text_lower for pattern in high_risk_patterns)


def contains_strong_legitimate_context(text: str) -> bool:
    """Return True when the message has ordinary work or project context."""
    text_lower = (text or "").lower()

    legitimate_patterns = [
        "meeting", "project", "presentation", "schedule", "server maintenance",
        "maintenance window", "tomorrow", "best regards", "regards", "department",
        "official", "shared with you", "work", "team update",
    ]

    return any(pattern in text_lower for pattern in legitimate_patterns)


def analyze_message_wording(text: str):
    """Score suspicious wording and return readable findings."""
    text_lower = (text or "").lower()
    score = 0
    findings = []

    found_words = [
        word for word in SUSPICIOUS_MESSAGE_WORDS
        if word in text_lower
    ]
    found_words = dedupe_keep_order(found_words)

    if found_words:
        score += min(len(found_words) * 8, 40)
        findings.append(
            "Message contains suspicious social-engineering wording: "
            + ", ".join(found_words)
        )

    if any(word in text_lower for word in [
        "expires", "expire", "today", "end of the day", "limited"
    ]):
        score += 15
        findings.append("Message creates urgency or pressure to act quickly")

    if any(word in text_lower for word in [
        "confirm", "verify", "identity", "details", "information"
    ]):
        score += 15
        findings.append(
            "Message asks the user to confirm or verify personal/account information"
        )

    if any(word in text_lower for word in [
        "password", "credentials", "payroll", "salary", "benefits", "bank account"
    ]):
        score += 10
        findings.append(
            "Message refers to sensitive account, payroll, or credential information"
        )

    return min(score, 65), dedupe_keep_order(findings)
