"""Final MsgGuard analysis orchestration and decision logic."""

from Backend.analyzers.brand_analyzer import (
    brand_domain_consistency_check,
    detect_brand_from_url,
    detect_claimed_brand,
)
from Backend.analyzers.domain_analyzer import (
    domain_age_verification,
    hosting_origin_consistency_analysis,
)
from Backend.analyzers.message_analyzer import (
    analyze_message_wording,
    contains_high_risk_phishing_language,
    contains_strong_legitimate_context,
)
from Backend.analyzers.url_analyzer import (
    analyze_url_structure,
    extract_text_without_urls,
    extract_urls,
    is_trusted_official_domain,
    is_url_only_input,
    normalize_domain,
)
from Backend.services.bert_service import bert_text_model_score
from Backend.utils.helpers import dedupe_keep_order


def is_safe_trusted_url_context(text: str, urls: list[str], url_results: list[dict]) -> bool:
    """Return True when every URL is trusted and no strong risk signal exists."""
    if not urls or not url_results:
        return False

    all_trusted = all(
        item.get("trustedOfficialDomain") is True
        for item in url_results
    )
    no_brand_risk = all(
        item.get("brandDomainScore", 0) == 0
        for item in url_results
    )
    no_structure_risk = all(
        item.get("urlStructureScore", 0) < 25
        for item in url_results
    )

    if not all_trusted or not no_brand_risk or not no_structure_risk:
        return False

    if contains_high_risk_phishing_language(text):
        return False

    return True


def analyze_input(text: str, claimed_brand=None) -> dict:
    """Run all relevant analyzers and return the final structured result."""
    urls = extract_urls(text)
    url_results = []
    reasons = []

    url_only_input = is_url_only_input(text, urls)

    if url_only_input:
        bert_score = 0
        bert_findings = []
        bert_probability = None
        wording_score = 0
        wording_findings = []

        reasons.append(
            "URL-only input detected; BERT text classification was skipped "
            "and URL analysis was used instead"
        )
    else:
        bert_score, bert_findings, bert_probability = bert_text_model_score(text)
        bert_findings = dedupe_keep_order(bert_findings)
        wording_score, wording_findings = analyze_message_wording(text)

    detected_brand = detect_claimed_brand(text, claimed_brand)

    total_domain_age_score = 0
    total_hosting_score = 0
    total_brand_score = 0
    highest_url_score = 0

    for url in urls:
        domain = normalize_domain(url)
        url_brand = detected_brand or detect_brand_from_url(url)

        age_score, age_findings, age_days, whois_info = domain_age_verification(domain)

        hosting_score, hosting_findings, origin_data = (
            hosting_origin_consistency_analysis(domain, url_brand)
        )

        brand_score, brand_findings = brand_domain_consistency_check(
            url,
            url_brand,
        )

        structure_score, structure_findings = analyze_url_structure(url)

        total_domain_age_score += age_score
        total_hosting_score += hosting_score
        total_brand_score += brand_score

        url_total_score = min(
            age_score + hosting_score + brand_score + structure_score,
            100,
        )
        highest_url_score = max(highest_url_score, url_total_score)

        url_results.append({
            "url": url,
            "domain": domain,
            "trustedOfficialDomain": is_trusted_official_domain(domain),
            "detectedBrandForUrl": url_brand,
            "domainAgeDays": age_days,
            "domainCreationDate": whois_info.get("creationDate"),
            "whoisInfo": whois_info,
            "hostingOrigin": origin_data,
            "domainAgeScore": age_score,
            "hostingOriginScore": hosting_score,
            "brandDomainScore": brand_score,
            "urlStructureScore": structure_score,
            "domainAgeFindings": dedupe_keep_order(age_findings),
            "hostingOriginFindings": dedupe_keep_order(hosting_findings),
            "brandDomainFindings": dedupe_keep_order(brand_findings),
            "urlStructureFindings": dedupe_keep_order(structure_findings),
            "totalUrlScore": url_total_score,
        })

    if not urls:
        reasons.append("No URL found in the message, so URL checks were not applied")

    url_score = min(highest_url_score, 80)

    if url_only_input:
        overall_score = url_score
    else:
        overall_score = max(bert_score, wording_score, url_score)

    if wording_score >= 25 and url_score >= 35:
        overall_score = max(overall_score, min(url_score + 15, 90))
        reasons.append(
            "Escalation applied: suspicious message wording combined with "
            "suspicious URL structure"
        )

    if total_brand_score >= 35:
        overall_score = max(overall_score, 70)
        reasons.append(
            "Escalation applied: suspicious brand-domain mismatch detected"
        )

    if (
        bert_probability is not None
        and bert_probability >= 0.80
        and url_score >= 30
    ):
        overall_score = max(overall_score, 75)
        reasons.append(
            "Escalation applied: high BERT phishing probability combined with "
            "suspicious URL signals"
        )

    if (
        not urls
        and bert_probability is not None
        and bert_probability >= 0.80
        and contains_high_risk_phishing_language(text)
    ):
        overall_score = max(overall_score, 70)
        reasons.append(
            "Escalation applied: high-risk phishing wording without URL"
        )

    trusted_safe_context = is_safe_trusted_url_context(
        text,
        urls,
        url_results,
    )

    if trusted_safe_context and is_url_only_input(text, urls):
        overall_score = 0
        reasons.append(
            "Trusted official URL-only input detected with no suspicious "
            "identity signals"
        )

    if trusted_safe_context and not is_url_only_input(text, urls):
        context_text = extract_text_without_urls(text, urls)

        if contains_strong_legitimate_context(context_text) and wording_score < 25:
            overall_score = max(0, overall_score - 25)
            reasons.append(
                "Trusted official domain detected with safe message context"
            )

    overall_score = min(round(overall_score), 100)

    if overall_score >= 60:
        status = "Phishing"
        risk_level = "High"
    elif overall_score >= 35:
        status = "Suspicious"
        risk_level = "Medium"
    else:
        status = "Legitimate"
        risk_level = "Low"

    message_findings = dedupe_keep_order(bert_findings + wording_findings)
    link_findings = []

    for item in url_results:
        link_findings.append(f"URL: {item.get('url')}")
        link_findings.append(f"Domain: {item.get('domain')}")
        link_findings.extend(item.get("urlStructureFindings", []))
        link_findings.extend(item.get("brandDomainFindings", []))

        whois_info = item.get("whoisInfo") or {}
        creation_date = item.get("domainCreationDate")

        if creation_date:
            link_findings.append(f"Domain creation date: {creation_date[:10]}")
        else:
            link_findings.append("Domain creation date: unavailable")

        if item.get("domainAgeDays") is not None:
            link_findings.append(
                f"Domain age: {item.get('domainAgeDays')} days"
            )
        else:
            link_findings.append("Domain age: unavailable")

        if whois_info.get("registrar"):
            link_findings.append(
                f"WHOIS registrar: {whois_info.get('registrar')}"
            )
        else:
            link_findings.append("WHOIS registrar: unavailable")

        hosting = item.get("hostingOrigin") or {}
        provider = hosting.get("org") or "unavailable"
        country = hosting.get("country") or "unavailable"
        country_code = hosting.get("country_code") or "unavailable"
        ip_address = hosting.get("ip") or "unavailable"

        link_findings.append(f"Hosting provider: {provider}")
        link_findings.append(
            f"Server location: {country} ({country_code})"
        )
        link_findings.append(f"Resolved IP address: {ip_address}")

    reasons.extend(message_findings)
    reasons.extend(link_findings)

    unique_reasons = dedupe_keep_order(reasons)

    return {
        "status": status,
        "riskLevel": risk_level,
        "riskScore": overall_score,
        "claimedBrand": detected_brand,
        "hasUrls": len(urls) > 0,
        "messageAnalysis": {
            "findings": message_findings,
            "bertFindings": bert_findings,
            "wordingFindings": wording_findings,
            "score": max(bert_score, wording_score),
            "confidence": bert_probability,
            "bertScore": bert_score,
            "bertPhishingProbability": bert_probability,
            "wordingScore": wording_score,
            "modelInputType": (
                "url_only" if url_only_input else "message_and_url_text"
            ),
            "bertSkippedForUrlOnly": url_only_input,
        },
        "scoreBreakdown": {
            "bertScore": bert_score,
            "wordingScore": wording_score,
            "urlScore": url_score,
            "highestUrlScore": highest_url_score,
            "totalDomainAgeScore": total_domain_age_score,
            "totalHostingOriginScore": total_hosting_score,
            "totalBrandDomainScore": total_brand_score,
            "urlCount": len(url_results),
        },
        "urlAnalyses": url_results,
        "reasons": unique_reasons,
        "findings": unique_reasons,
        "topReasons": unique_reasons[:5],
    }
