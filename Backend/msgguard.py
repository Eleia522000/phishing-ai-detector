# -*- coding: utf-8 -*-

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
from urllib.parse import urlparse
from datetime import datetime, timezone
import time
import socket
import requests
import whois
import tldextract
import re
from difflib import SequenceMatcher

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification


app = Flask(__name__)
CORS(app)

print("RUNNING MSGGUARD BACKEND VERSION: HOSTING_PROVIDER_TEXT_V2")

# --------------------------------------------------
# MongoDB Atlas configuration
# --------------------------------------------------
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "phishing_ai_detector_db")
MONGO_COLLECTION_NAME = os.getenv("MONGO_COLLECTION_NAME", "analysis_logs")

mongo_collection = None

try:
    if MONGO_URI:
        mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        mongo_client.admin.command("ping")
        mongo_db = mongo_client[MONGO_DB_NAME]
        mongo_collection = mongo_db[MONGO_COLLECTION_NAME]
        print("MongoDB connected successfully")
    else:
        print("MONGO_URI not found. Database logging disabled.")
except Exception as e:
    print(f"MongoDB connection failed: {e}")
    mongo_collection = None


PROJECT_DIR = Path(__file__).resolve().parent.parent
BERT_MODEL_PATH = PROJECT_DIR / "models" / "bert_model"


bert_tokenizer = None
bert_model = None
BERT_AVAILABLE = False

print("BERT path:", BERT_MODEL_PATH)
print("BERT exists:", BERT_MODEL_PATH.exists())

try:
    if BERT_MODEL_PATH.exists():
        bert_tokenizer = AutoTokenizer.from_pretrained(
            str(BERT_MODEL_PATH),
            local_files_only=True
        )
        bert_model = AutoModelForSequenceClassification.from_pretrained(
            str(BERT_MODEL_PATH),
            local_files_only=True
        )
        bert_model.eval()
        BERT_AVAILABLE = True
        print("BERT model loaded successfully")
    else:
        print("BERT model folder not found. Backend will run without BERT.")
except Exception as e:
    print(f"BERT model loading failed: {e}")
    print("Backend will continue running without BERT.")


OFFICIAL_BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "youtube": "youtube.com",
    "bankhapoalim": "bankhapoalim.co.il",
    "leumi": "leumi.co.il",
    "discount": "discountbank.co.il",
    "isracard": "isracard.co.il",
    "visa": "visa.com",
    "mastercard": "mastercard.com",
}

TRUSTED_BRAND_DOMAINS = {
    "youtube": ["youtube.com", "youtu.be"],
    "google": ["google.com", "gmail.com", "goo.gl"],
    "paypal": ["paypal.com", "paypal.me"],
    "amazon": ["amazon.com", "amazon.co.uk"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
}


def is_trusted_official_domain(domain):
    """
    Checks whether a normalized registered domain belongs to the trusted official
    domain list. This reduces false positives for real domains such as amazon.com.
    """
    domain = (domain or "").lower().strip()

    for trusted_domains in TRUSTED_BRAND_DOMAINS.values():
        if domain in trusted_domains:
            return True

    return False

EXPECTED_BRAND_REGIONS = {
    "paypal": ["US"],
    "amazon": ["US"],
    "apple": ["US"],
    "microsoft": ["US"],
    "google": ["US"],
    "youtube": ["US"],
    "bankhapoalim": ["IL"],
    "leumi": ["IL"],
    "discount": ["IL"],
    "isracard": ["IL"],
    "visa": ["US"],
    "mastercard": ["US"],
}


def extract_urls(text):
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?)'
    urls = re.findall(url_pattern, text or "")
    cleaned_urls = []

    for url in urls:
        url = url.rstrip('.,);]>"\'')
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        cleaned_urls.append(url)

    return cleaned_urls


def normalize_domain(url):
    parsed = urlparse(url)
    netloc = parsed.netloc.lower().strip()

    if ":" in netloc:
        netloc = netloc.split(":")[0]

    extracted = tldextract.extract(netloc)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    return netloc


def extract_subdomain(url):
    parsed = urlparse(url)
    netloc = parsed.netloc.lower().strip()

    if ":" in netloc:
        netloc = netloc.split(":")[0]

    extracted = tldextract.extract(netloc)
    return extracted.subdomain.lower() if extracted.subdomain else ""


def calculate_similarity(a, b):
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def edit_distance(s1, s2):
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
                    dp[i - 1][j - 1]
                )

    return dp[n][m]


def normalize_homoglyphs(text):
    """
    Normalize common phishing character substitutions.
    Examples:
    amaz0n -> amazon
    g00gle -> google
    paypa1 -> paypal
    """
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


def split_domain_tokens(domain_text):
    """
    Split domains like amaz0n-delivery-check into:
    ["amaz0n", "delivery", "check"]
    """
    return [token for token in re.split(r"[^a-zA-Z0-9]+", domain_text.lower()) if token]


def extract_domain_parts(url):
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
    }


def detect_brand_from_url(url):
    """
    Infer brand impersonation directly from the URL.
    Example:
    http://amaz0n-delivery-check.com -> amazon
    """
    parts = extract_domain_parts(url)

    candidates = [
        parts["domain"],
        normalize_homoglyphs(parts["domain"]),
        parts["subdomain"],
        normalize_homoglyphs(parts["subdomain"]),
    ]

    candidates.extend(split_domain_tokens(parts["domain"]))
    candidates.extend([normalize_homoglyphs(t) for t in split_domain_tokens(parts["domain"])])

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


def safe_get_creation_date(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            return creation_date
    except Exception:
        pass

    return None


def compute_domain_age_days(domain):
    creation_date = safe_get_creation_date(domain)

    if not creation_date:
        return None

    now = datetime.now(timezone.utc)
    return (now - creation_date).days


def domain_age_verification(domain):
    score = 0
    findings = []
    age_days = compute_domain_age_days(domain)

    if age_days is None:
        findings.append("Could not retrieve domain creation date")
        return score, findings, None

    findings.append(f"Domain age: {age_days} days")

    if age_days < 30:
        score += 25
        findings.append("Very recently registered domain")
    elif age_days < 180:
        score += 15
        findings.append("Relatively new domain")
    elif age_days < 365:
        score += 8
        findings.append("Moderately young domain")
    else:
        findings.append("Domain age appears less suspicious")

    return score, findings, age_days


def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def lookup_hosting_origin(ip_address):
    if not ip_address:
        return None

    try:
        response = requests.get(f"https://ipwho.is/{ip_address}", timeout=5)
        data = response.json()

        if data.get("success"):
            return {
                "ip": ip_address,
                "country_code": data.get("country_code"),
                "country": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "org": data.get("connection", {}).get("org"),
            }
    except Exception:
        pass

    return None


def hosting_origin_consistency_analysis(domain, brand):
    score = 0
    findings = []

    ip_address = resolve_ip(domain)
    origin_data = lookup_hosting_origin(ip_address)

    if not origin_data:
        findings.append("Could not retrieve hosting-origin information")
        return score, findings, None

    country_code = origin_data.get("country_code")

    provider_name = origin_data.get("org") or "Unknown provider"

    findings.append(f"Hosting provider: {provider_name}")
    findings.append(f"Server location: {origin_data.get('country')} ({country_code})")

    if brand and brand in EXPECTED_BRAND_REGIONS:
        expected_regions = EXPECTED_BRAND_REGIONS[brand]
        if country_code not in expected_regions:
            score += 15
            findings.append(
                f"Hosting-origin mismatch: expected one of {expected_regions}, got {country_code}"
            )
        else:
            findings.append("Hosting origin is consistent with expected brand region")
    else:
        findings.append("No claimed brand available for hosting-origin comparison")

    return score, findings, origin_data


def detect_claimed_brand(text, claimed_brand=None):
    if claimed_brand:
        brand = claimed_brand.lower().strip()
        if brand in OFFICIAL_BRAND_DOMAINS:
            return brand

    text_lower = (text or "").lower()
    normalized_text = normalize_homoglyphs(text_lower)

    for brand in OFFICIAL_BRAND_DOMAINS.keys():
        if brand in text_lower or brand in normalized_text:
            return brand

    return None


def brand_domain_consistency_check(url, brand):
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
    normalized_similarity = calculate_similarity(observed_main_normalized, official_main_normalized)
    distance = edit_distance(observed_main, official_main)
    normalized_distance = edit_distance(observed_main_normalized, official_main_normalized)

    if normalized_similarity >= 0.80 or normalized_distance <= 2:
        score += 35
        findings.append("Domain appears to imitate the official brand using character substitution")

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
        findings.append(f"Observed domain differs from official brand by {distance} character(s)")

    if domain.split(".")[-1] != official_domain.split(".")[-1]:
        score += 10
        findings.append("TLD differs from the official brand domain")

    if score == 0:
        findings.append("No strong brand-domain inconsistency detected")

    return min(score, 60), findings

def bert_text_model_score(text):
    """
    The saved BERT model was trained as binary classification:
    0 = legitimate_email + legitimate_url
    1 = phishing_email + phishing_url
    """
    if not BERT_AVAILABLE or bert_tokenizer is None or bert_model is None:
        return 0, ["BERT model is not available. Train the model first and save it under models/bert_model."], None

    try:
        inputs = bert_tokenizer(
            text,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=128
        )

        with torch.no_grad():
            outputs = bert_model(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=1)

        phishing_probability = probabilities[0][1].item()
        score = int(phishing_probability * 50)

        findings = [f"BERT phishing probability: {phishing_probability:.2%}"]

        if phishing_probability >= 0.80:
            findings.append("High-risk phishing pattern detected by BERT model")
        elif phishing_probability >= 0.50:
            findings.append("Moderate phishing pattern detected by BERT model")
        else:
            findings.append("Low phishing probability according to BERT model")

        return score, findings, phishing_probability

    except Exception as e:
        return 0, [f"BERT model could not analyze input: {str(e)}"], None


def analyze_input(text, claimed_brand=None):
    urls = extract_urls(text)
    reasons = []
    url_results = []

    bert_score, bert_findings, bert_probability = bert_text_model_score(text)
    reasons.extend(bert_findings)

    detected_brand = detect_claimed_brand(text, claimed_brand)

    total_domain_age_score = 0
    total_hosting_score = 0
    total_brand_score = 0

    for url in urls:
        domain = normalize_domain(url)

        # If the message did not mention a brand, infer it from suspicious URL similarity.
        url_brand = detected_brand or detect_brand_from_url(url)

        age_score, age_findings, age_days = domain_age_verification(domain)
        hosting_score, hosting_findings, origin_data = hosting_origin_consistency_analysis(
            domain,
            url_brand
        )
        brand_score, brand_findings = brand_domain_consistency_check(url, url_brand)

        total_domain_age_score += age_score
        total_hosting_score += hosting_score
        total_brand_score += brand_score

        reasons.extend(age_findings)
        reasons.extend(hosting_findings)
        reasons.extend(brand_findings)

        url_results.append({
            "url": url,
            "domain": domain,
            "trustedOfficialDomain": is_trusted_official_domain(domain),
            "detectedBrandForUrl": url_brand,
            "domainAgeDays": age_days,
            "hostingOrigin": origin_data,
            "domainAgeScore": age_score,
            "hostingOriginScore": hosting_score,
            "brandDomainScore": brand_score,
            "domainAgeFindings": age_findings,
            "hostingOriginFindings": hosting_findings,
            "brandDomainFindings": brand_findings,
            "totalUrlScore": age_score + hosting_score + brand_score,
        })

    if not urls:
        reasons.append("No URL found in the message, so identity-based URL checks were not applied")

    url_score = min(total_domain_age_score + total_hosting_score + total_brand_score, 60)
    overall_score = min(bert_score + url_score, 100)

    # Trust Score:
    # Risk signals increase the score.
    # Trust signals reduce false positives only when URL identity checks did not find real risk.
    trust_score = 0
    trust_reasons = []

    for item in url_results:
        domain = item.get("domain", "")

        if item.get("trustedOfficialDomain") is True:
            trust_score += 40
            trust_reasons.append(f"Trusted official domain detected: {domain}")

        if item.get("domainAgeDays") is not None and item.get("domainAgeDays") > 365:
            trust_score += 10
            trust_reasons.append(f"Domain is older than one year: {domain}")

        if item.get("brandDomainScore", 0) == 0:
            trust_score += 10
            trust_reasons.append(f"No brand-domain mismatch detected: {domain}")

    trust_score = min(trust_score, 60)

    # Apply trust reduction only when there are no suspicious URL identity signals.
    # This keeps phishing domains like amaz0n/paypa1/g00gle risky.
    if trust_score > 0 and url_score == 0:
        overall_score = max(0, overall_score - trust_score)
        reasons.extend(trust_reasons)

    if url_score >= 45:
        overall_score = max(overall_score, 70)
        reasons.append("Escalation applied: strong suspicious URL identity signals detected")

    if bert_probability is not None and bert_probability >= 0.80 and url_score >= 20:
        overall_score = max(overall_score, 75)
        reasons.append("Escalation applied: high BERT phishing probability combined with suspicious URL identity signals")

    if overall_score >= 60:
        status = "Phishing"
        risk_level = "High"
    elif overall_score >= 35:
        status = "Suspicious"
        risk_level = "Medium"
    else:
        status = "Legitimate"
        risk_level = "Low"

    seen = set()
    unique_reasons = []
    for reason in reasons:
        if reason not in seen:
            unique_reasons.append(reason)
            seen.add(reason)

    return {
        "status": status,
        "riskLevel": risk_level,
        "riskScore": overall_score,
        "claimedBrand": detected_brand,
        "hasUrls": len(urls) > 0,
        "messageAnalysis": {
            "bertFindings": bert_findings,
            "wordingFindings": bert_findings,
            "findings": bert_findings,
            "score": bert_score,
            "confidence": bert_probability,
            "bertScore": bert_score,
            "bertPhishingProbability": bert_probability,
            "modelInputType": "message_and_url_text",
        },
        "scoreBreakdown": {
            "bertScore": bert_score,
            "urlScore": url_score,
            "trustScore": trust_score,
            "totalDomainAgeScore": total_domain_age_score,
            "totalHostingOriginScore": total_hosting_score,
            "totalBrandDomainScore": total_brand_score,
            "urlCount": len(url_results),
        },
        "urlAnalyses": url_results,
        "reasons": unique_reasons,
        "findings": unique_reasons,
        "topReasons": unique_reasons,
    }


def save_analysis_to_db(input_text, result, response_time):
    """
    Save each analysis result to MongoDB Atlas for future review,
    feedback labeling, and model retraining.
    The system continues working even if MongoDB is unavailable.
    """
    if mongo_collection is None:
        return

    try:
        document = {
            "input_text": input_text,
            "status": result.get("status"),
            "risk_level": result.get("riskLevel"),
            "risk_score": result.get("riskScore"),
            "claimed_brand": result.get("claimedBrand"),
            "has_urls": result.get("hasUrls"),
            "message_analysis": result.get("messageAnalysis"),
            "score_breakdown": result.get("scoreBreakdown"),
            "url_analyses": result.get("urlAnalyses"),
            "reasons": result.get("reasons"),
            "model_prediction": result.get("status"),
            "real_label": None,
            "verified_by_user": False,
            "response_time": response_time,
            "created_at": datetime.utcnow(),
        }

        mongo_collection.insert_one(document)
        print("Analysis saved to MongoDB")

    except Exception as e:
        print(f"Failed to save analysis to MongoDB: {e}")


@app.route("/", methods=["GET"])
def home():
    return "MsgGuard backend works with BERT, message analysis, homoglyph detection, and URL identity checks"


@app.route("/analyze", methods=["GET", "POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    if request.method == "GET":
        text = str(request.args.get("text", "")).strip()
        claimed_brand = (request.args.get("claimedBrand") or "").strip() or None

        if not text:
            return jsonify({"error": "Input text cannot be empty"}), 400

        start_time = time.time()
        result = analyze_input(text, claimed_brand)
        response_time = time.time() - start_time

        result["responseTime"] = response_time
        save_analysis_to_db(text, result, response_time)

        return jsonify(result)

    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    text = str(data.get("text", "")).strip()
    claimed_brand = (data.get("claimedBrand") or "").strip() or None

    if not text:
        return jsonify({"error": "Input text cannot be empty"}), 400

    start_time = time.time()
    result = analyze_input(text, claimed_brand)
    response_time = time.time() - start_time

    result["responseTime"] = response_time
    save_analysis_to_db(text, result, response_time)

    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)





