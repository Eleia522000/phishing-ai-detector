"""Brand detection and brand-domain consistency analysis."""

from Backend.config import OFFICIAL_BRAND_DOMAINS, TRUSTED_BRAND_DOMAINS
from Backend.analyzers.url_analyzer import extract_domain_parts
from Backend.utils.helpers import (
    calculate_similarity,
    dedupe_keep_order,
    edit_distance,
    normalize_homoglyphs,
    split_domain_tokens,
)


def detect_brand_from_url(url: str):
    """Infer an imitated brand directly from URL similarity."""
    parts = extract_domain_parts(url)

    candidates = [
        parts["domain"],
        normalize_homoglyphs(parts["domain"]),
        parts["subdomain"],
        normalize_homoglyphs(parts["subdomain"]),
    ]

    candidates.extend(split_domain_tokens(parts["domain"]))
    candidates.extend([
        normalize_homoglyphs(token)
        for token in split_domain_tokens(parts["domain"])
    ])
    candidates.extend(split_domain_tokens(parts["subdomain"]))
    candidates.extend([
        normalize_homoglyphs(token)
        for token in split_domain_tokens(parts["subdomain"])
    ])

    for brand, official_domain in OFFICIAL_BRAND_DOMAINS.items():
        official_main = official_domain.split(".")[0]

        for candidate in candidates:
            if not candidate:
                continue

            similarity = calculate_similarity(candidate, official_main)
            distance = edit_distance(candidate, official_main)

            if candidate == brand or candidate == official_main:
                return brand

            if similarity >= 0.82 or distance <= 2:
                return brand

    return None


def detect_claimed_brand(text: str, claimed_brand=None):
    """Detect a claimed brand from explicit input or from message text."""
    if claimed_brand:
        brand = claimed_brand.lower().strip()
        if brand in OFFICIAL_BRAND_DOMAINS:
            return brand

    text_lower = (text or "").lower()
    normalized_text = normalize_homoglyphs(text_lower)

    for brand in OFFICIAL_BRAND_DOMAINS:
        if brand in text_lower or brand in normalized_text:
            return brand

    return None


def brand_domain_consistency_check(url: str, brand):
    """Compare the observed registered domain with a claimed brand identity."""
    score = 0
    findings = []

    parts = extract_domain_parts(url)
    domain = parts["registered_domain"]
    subdomain = parts["subdomain"]
    observed_main = parts["domain"]
    observed_main_normalized = normalize_homoglyphs(observed_main)

    url_detected_brand = detect_brand_from_url(url)

    if not brand and url_detected_brand:
        brand = url_detected_brand
        findings.append(f"Claimed brand inferred from URL similarity: {brand}")

    if not brand:
        findings.append("No claimed brand detected for brand-domain consistency check")
        return score, findings

    official_domain = OFFICIAL_BRAND_DOMAINS.get(brand)

    if not official_domain:
        findings.append("Claimed brand not found in official domain database")
        return score, findings

    trusted_domains = TRUSTED_BRAND_DOMAINS.get(brand, [official_domain])
    official_main = official_domain.split(".")[0]
    official_main_normalized = normalize_homoglyphs(official_main)

    findings.append(f"Claimed brand: {brand}")
    findings.append(f"Observed domain: {domain}")
    findings.append(f"Expected official domain: {official_domain}")

    if domain in trusted_domains:
        findings.append("Domain matches official or trusted brand domain")
        return score, findings

    similarity = calculate_similarity(observed_main, official_main)
    normalized_similarity = calculate_similarity(
        observed_main_normalized,
        official_main_normalized,
    )
    distance = edit_distance(observed_main, official_main)
    normalized_distance = edit_distance(
        observed_main_normalized,
        official_main_normalized,
    )

    if normalized_similarity >= 0.80 or normalized_distance <= 2:
        score += 35
        findings.append(
            "Domain appears to imitate the official brand using character substitution"
        )

    if brand in observed_main_normalized and domain not in trusted_domains:
        score += 25
        findings.append("Brand name appears inside a non-official main domain")

    normalized_subdomain = normalize_homoglyphs(subdomain)
    if brand in normalized_subdomain and domain not in trusted_domains:
        score += 25
        findings.append("Brand name appears in subdomain but main domain is different")

    if similarity >= 0.80:
        score += 15
        findings.append("Observed domain closely resembles the official brand domain")

    if distance in [1, 2]:
        score += 15
        findings.append(
            f"Observed domain differs from official brand by {distance} character(s)"
        )

    if domain.split(".")[-1] != official_domain.split(".")[-1]:
        score += 10
        findings.append("TLD differs from the official brand domain")

    if score == 0:
        findings.append("No strong brand-domain inconsistency detected")

    return min(score, 60), dedupe_keep_order(findings)
