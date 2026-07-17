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
    """Infer a likely imitated brand by comparing URL components with known brands."""
    parts = extract_domain_parts(url)

    # Build a broad list of URL components that may contain a brand name.
    # Both original and homoglyph-normalized values are included so visually
    # similar character substitutions can still be detected.
    candidates = [
        parts["domain"],
        normalize_homoglyphs(parts["domain"]),
        parts["subdomain"],
        normalize_homoglyphs(parts["subdomain"]),
    ]

    # Add individual tokens from the main domain and subdomain because brand
    # names may appear inside longer values separated by hyphens or other marks.
    domain_tokens = split_domain_tokens(parts["domain"])
    subdomain_tokens = split_domain_tokens(parts["subdomain"])

    candidates.extend(domain_tokens)
    candidates.extend([
        normalize_homoglyphs(token)
        for token in domain_tokens
    ])
    candidates.extend(subdomain_tokens)
    candidates.extend([
        normalize_homoglyphs(token)
        for token in subdomain_tokens
    ])

    # Compare every candidate value with each known official brand domain.
    for brand, official_domain in OFFICIAL_BRAND_DOMAINS.items():
        official_main = official_domain.split(".")[0]

        for candidate in candidates:
            if not candidate:
                continue

            similarity = calculate_similarity(candidate, official_main)
            distance = edit_distance(candidate, official_main)

            # An exact match provides the strongest indication of the brand.
            if candidate == brand or candidate == official_main:
                return brand

            # Close similarity or a very small edit distance may indicate
            # typosquatting or another form of brand imitation.
            if similarity >= 0.82 or distance <= 2:
                return brand

    return None


def detect_claimed_brand(text: str, claimed_brand=None):
    """Detect a claimed brand from explicit input or from the submitted message."""
    # Prefer an explicitly supplied brand when it exists in the known-brand list.
    if claimed_brand:
        brand = claimed_brand.lower().strip()
        if brand in OFFICIAL_BRAND_DOMAINS:
            return brand

    # Search both the original text and a homoglyph-normalized version so
    # visually altered brand names can still be identified.
    text_lower = (text or "").lower()
    normalized_text = normalize_homoglyphs(text_lower)

    for brand in OFFICIAL_BRAND_DOMAINS:
        if brand in text_lower or brand in normalized_text:
            return brand

    return None


def brand_domain_consistency_check(url: str, brand):
    """Compare the observed domain with the expected domain of a claimed brand."""
    score = 0
    findings = []

    # Extract the registered domain, subdomain, and primary domain label used
    # for brand comparison.
    parts = extract_domain_parts(url)
    domain = parts["registered_domain"]
    subdomain = parts["subdomain"]
    observed_main = parts["domain"]
    observed_main_normalized = normalize_homoglyphs(observed_main)

    # Attempt to infer a brand directly from the URL when no brand was supplied.
    url_detected_brand = detect_brand_from_url(url)

    if not brand and url_detected_brand:
        brand = url_detected_brand
        findings.append(f"Claimed brand inferred from URL similarity: {brand}")

    # Stop the check when no brand identity can be established.
    if not brand:
        findings.append(
            "No claimed brand detected for brand-domain consistency check"
        )
        return score, findings

    # Retrieve the expected official domain for the identified brand.
    official_domain = OFFICIAL_BRAND_DOMAINS.get(brand)

    if not official_domain:
        findings.append("Claimed brand not found in official domain database")
        return score, findings

    # Some brands legitimately use more than one trusted domain.
    trusted_domains = TRUSTED_BRAND_DOMAINS.get(brand, [official_domain])
    official_main = official_domain.split(".")[0]
    official_main_normalized = normalize_homoglyphs(official_main)

    findings.append(f"Claimed brand: {brand}")
    findings.append(f"Observed domain: {domain}")
    findings.append(f"Expected official domain: {official_domain}")

    # A known trusted domain is considered consistent and receives no risk score.
    if domain in trusted_domains:
        findings.append("Domain matches official or trusted brand domain")
        return score, findings

    # Compare the observed main domain with the official brand label using
    # both raw and homoglyph-normalized values.
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

    # Strong normalized similarity may indicate deliberate character
    # substitution such as replacing letters with visually similar symbols.
    if normalized_similarity >= 0.80 or normalized_distance <= 2:
        score += 35
        findings.append(
            "Domain appears to imitate the official brand using character substitution"
        )

    # Penalize non-official domains that contain the brand name directly.
    if brand in observed_main_normalized and domain not in trusted_domains:
        score += 25
        findings.append("Brand name appears inside a non-official main domain")

    # Penalize URLs that place the brand name only in the subdomain while the
    # actual registered domain belongs to a different entity.
    normalized_subdomain = normalize_homoglyphs(subdomain)
    if brand in normalized_subdomain and domain not in trusted_domains:
        score += 25
        findings.append(
            "Brand name appears in subdomain but main domain is different"
        )

    # High textual similarity can indicate a lookalike or typosquatted domain.
    if similarity >= 0.80:
        score += 15
        findings.append(
            "Observed domain closely resembles the official brand domain"
        )

    # A one- or two-character difference is a common typosquatting pattern.
    if distance in [1, 2]:
        score += 15
        findings.append(
            f"Observed domain differs from official brand by {distance} character(s)"
        )

    # A different top-level domain can strengthen evidence of impersonation.
    if domain.split(".")[-1] != official_domain.split(".")[-1]:
        score += 10
        findings.append("TLD differs from the official brand domain")

    if score == 0:
        findings.append("No strong brand-domain inconsistency detected")

    # Limit this analyzer's contribution and remove duplicate findings while
    # preserving their original order.
    return min(score, 60), dedupe_keep_order(findings)