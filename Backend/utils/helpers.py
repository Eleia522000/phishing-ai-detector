"""Small reusable helper functions used by multiple backend modules."""

import re
from difflib import SequenceMatcher
from typing import Iterable, List, Optional, TypeVar

T = TypeVar("T")


def dedupe_keep_order(items: Iterable[T]) -> List[T]:
    """Remove duplicate non-empty items while preserving their original order."""
    seen = set()
    clean = []

    for item in items:
        if item and item not in seen:
            clean.append(item)
            seen.add(item)

    return clean


def calculate_similarity(a: str, b: str) -> float:
    """Return a SequenceMatcher similarity score between two strings."""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def edit_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein edit distance using dynamic programming."""
    s1 = s1.lower()
    s2 = s2.lower()

    n, m = len(s1), len(s2)
    dp = [[0] * (m + 1) for _ in range(n + 1)]

    for i in range(n + 1):
        dp[i][0] = i

    for j in range(m + 1):
        dp[0][j] = j

    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(
                    dp[i - 1][j],
                    dp[i][j - 1],
                    dp[i - 1][j - 1],
                )

    return dp[n][m]


def normalize_homoglyphs(text: Optional[str]) -> str:
    """Normalize common character substitutions used in phishing domains."""
    replacements = {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "|": "l",
    }

    normalized = (text or "").lower()

    for fake, real in replacements.items():
        normalized = normalized.replace(fake, real)

    return normalized


def split_domain_tokens(domain_text: str) -> List[str]:
    """Split a domain label into alphanumeric tokens."""
    return [
        token
        for token in re.split(r"[^a-zA-Z0-9]+", domain_text.lower())
        if token
    ]
