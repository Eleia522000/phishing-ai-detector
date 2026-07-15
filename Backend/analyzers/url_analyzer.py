"""URL extraction, normalization, and structure analysis."""

import re
from urllib.parse import urlparse

import tldextract

from Backend.config import SUSPICIOUS_URL_WORDS, TRUSTED_BRAND_DOMAINS
from Backend.utils.helpers import dedupe_keep_order


def is_trusted_official_domain(domain: str) -> bool:
    """Return True when a registered domain appears in the trusted-domain list."""
    domain = (domain or "").lower().strip()

    for trusted_domains in TRUSTED_BRAND_DOMAINS.values():
        if domain in trusted_domains:
            return True

    return False


def is_url_only_input(text: str, urls: list[str]) -> bool:
    """Return True when the submitted input contains only one URL."""
    if not text or not urls or len(urls) != 1:
        return False

    original_text = text.strip().lower().rstrip("/")
    url = urls[0].strip().lower().rstrip("/")

    candidates = {
        url,
        url.replace("http://", ""),
        url.replace("https://", ""),
        url.replace("http://www.", ""),
        url.replace("https://www.", ""),
        url.replace("www.", ""),
    }

    return original_text in candidates


def extract_text_without_urls(text: str, urls: list[str]) -> str:
    """Remove extracted URLs and return the remaining message context."""
    clean_text = text or ""

    for url in urls:
        raw_url = url
        no_http = url.replace("http://", "").replace("https://", "")
        no_www = no_http.replace("www.", "")

        for candidate in [raw_url, no_http, no_www]:
            clean_text = clean_text.replace(candidate, " ")

    return re.sub(r"\s+", " ", clean_text).strip()


def extract_urls(text: str) -> list[str]:
    """Extract, normalize, and deduplicate URLs from submitted text."""
    url_pattern = (
        r"(https?://[^\s]+|www\.[^\s]+|"
        r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?)"
    )
    urls = re.findall(url_pattern, text or "")
    cleaned_urls = []

    for url in urls:
        url = url.rstrip('.,);]>"\'')
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        cleaned_urls.append(url)

    return dedupe_keep_order(cleaned_urls)


def normalize_domain(url: str) -> str:
    """Return the registered domain extracted from a URL."""
    parsed = urlparse(url)
    netloc = parsed.netloc.lower().strip()

    if ":" in netloc:
        netloc = netloc.split(":")[0]

    extracted = tldextract.extract(netloc)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    return netloc


def extract_subdomain(url: str) -> str:
    """Return the subdomain portion of a URL."""
    parsed = urlparse(url)
    netloc = parsed.netloc.lower().strip()

    if ":" in netloc:
        netloc = netloc.split(":")[0]

    extracted = tldextract.extract(netloc)
    return extracted.subdomain.lower() if extracted.subdomain else ""


def extract_domain_parts(url: str) -> dict:
    """Return hostname, subdomain, main label, suffix, and registered domain."""
    parsed = urlparse(url)
    netloc = parsed.netloc.lower().strip()

    if ":" in netloc:
        netloc = netloc.split(":")[0]

    extracted = tldextract.extract(netloc)

    registered_domain = netloc
    if extracted.domain and extracted.suffix:
        registered_domain = f"{extracted.domain}.{extracted.suffix}"

    return {
        "subdomain": extracted.subdomain.lower() if extracted.subdomain else "",
        "domain": extracted.domain.lower() if extracted.domain else "",
        "suffix": extracted.suffix.lower() if extracted.suffix else "",
        "registered_domain": registered_domain,
        "hostname": netloc,
    }


def analyze_url_structure(url: str):
    """Score suspicious lexical and structural URL indicators."""
    parsed = urlparse(url)

    hostname = parsed.netloc.lower().strip()
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    path = parsed.path.lower().strip()

    parts = extract_domain_parts(url)
    registered_domain = parts["registered_domain"]
    subdomain = parts["subdomain"]

    score = 0
    findings = []
    full_url_text = f"{hostname} {path}"

    found_words = [
        word for word in SUSPICIOUS_URL_WORDS
        if word in full_url_text
    ]
    found_words = dedupe_keep_order(found_words)

    if found_words:
        score += min(len(found_words) * 10, 50)
        findings.append(
            "URL contains phishing-related words: " + ", ".join(found_words)
        )

    if subdomain:
        subdomain_parts = subdomain.split(".")
        score += 10
        findings.append("URL uses a subdomain before the main registered domain")

        if len(subdomain_parts) >= 2:
            score += 10
            findings.append("URL uses multiple subdomain levels")

    if "-" in hostname:
        score += 10
        findings.append("Hostname contains hyphenated words, common in fake portal URLs")

    if any(word in path for word in [
        "login", "verify", "confirm", "identity", "auth", "session"
    ]):
        score += 20
        findings.append("URL path looks like login, verification, or identity-confirmation flow")

    if is_trusted_official_domain(registered_domain):
        score = max(0, score - 40)
        findings.append("Registered domain is in the trusted official domain list")

    return min(score, 75), dedupe_keep_order(findings)
