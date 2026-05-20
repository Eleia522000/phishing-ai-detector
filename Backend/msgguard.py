import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
from datetime import datetime, timezone
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

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# -----------------------------
# BERT MODEL LOADING
# -----------------------------
BERT_MODEL_PATH = os.path.join(BASE_DIR, "models", "bert_model")

bert_tokenizer = AutoTokenizer.from_pretrained(BERT_MODEL_PATH)
bert_model = AutoModelForSequenceClassification.from_pretrained(BERT_MODEL_PATH)
bert_model.eval()

OFFICIAL_BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "bankhapoalim": "bankhapoalim.co.il",
    "leumi": "leumi.co.il",
    "discount": "discountbank.co.il",
    "isracard": "isracard.co.il",
    "visa": "visa.com",
    "mastercard": "mastercard.com",
}

EXPECTED_BRAND_REGIONS = {
    "paypal": ["US"],
    "amazon": ["US"],
    "apple": ["US"],
    "microsoft": ["US"],
    "google": ["US"],
    "bankhapoalim": ["IL"],
    "leumi": ["IL"],
    "discount": ["IL"],
    "isracard": ["IL"],
    "visa": ["US"],
    "mastercard": ["US"],
}


def extract_urls(text):
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?)'
    urls = re.findall(url_pattern, text)
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


def detect_claimed_brand(text, claimed_brand=None):
    if claimed_brand:
        brand = claimed_brand.lower().strip()
        if brand in OFFICIAL_BRAND_DOMAINS:
            return brand

    text_lower = text.lower()

    for brand in OFFICIAL_BRAND_DOMAINS.keys():
        if brand in text_lower:
            return brand

    return None


def bert_text_model_score(text):
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

        # BERT is the main AI score, up to 50 points
        score = int(phishing_probability * 50)

        explanations = [f"BERT phishing probability: {phishing_probability:.2%}"]

        if phishing_probability >= 0.80:
            explanations.append("High-risk phishing pattern detected by BERT model")
        elif phishing_probability >= 0.50:
            explanations.append("Moderate phishing pattern detected by BERT model")
        else:
            explanations.append("Low phishing probability according to BERT model")

        return score, explanations, phishing_probability

    except Exception as e:
        return 0, [f"BERT model could not analyze input: {str(e)}"], None


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


def hosting_origin_consistency_analysis(domain, brand):
    score = 0
    findings = []

    ip_address = resolve_ip(domain)
    origin_data = lookup_hosting_origin(ip_address)

    if not origin_data:
        findings.append("Could not retrieve hosting-origin information")
        return score, findings, None

    country_code = origin_data.get("country_code")

    findings.append(
        f"Hosting origin detected: {origin_data.get('country')} ({country_code}), "
        f"Org: {origin_data.get('org')}"
    )

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


def brand_domain_consistency_check(url, brand):
    score = 0
    findings = []

    domain = normalize_domain(url)
    subdomain = extract_subdomain(url)

    if not brand:
        findings.append("No claimed brand detected for brand-domain consistency check")
        return score, findings

    official_domain = OFFICIAL_BRAND_DOMAINS.get(brand)

    if not official_domain:
        findings.append("Claimed brand not found in official domain database")
        return score, findings

    findings.append(f"Claimed brand: {brand}")
    findings.append(f"Observed domain: {domain}")
    findings.append(f"Expected official domain: {official_domain}")

    if domain == official_domain:
        findings.append("Domain matches official brand domain")
        return score, findings

    observed_main = domain.split(".")[0]
    official_main = official_domain.split(".")[0]
    similarity = calculate_similarity(observed_main, official_main)

    if brand in subdomain and domain != official_domain:
        score += 20
        findings.append("Brand name appears in subdomain but main domain is different")

    if similarity >= 0.75:
        score += 20
        findings.append("Observed domain closely resembles the official brand domain")

    if domain.split(".")[-1] != official_domain.split(".")[-1]:
        score += 10
        findings.append("TLD differs from the official brand domain")

    if score == 0:
        findings.append("No strong brand-domain inconsistency detected")

    return score, findings


def analyze_input(text, claimed_brand=None):
    urls = extract_urls(text)

    overall_score = 0
    reasons = []

    bert_score, bert_findings, bert_probability = bert_text_model_score(text)

    overall_score += bert_score
    reasons.extend(bert_findings)

    detected_brand = detect_claimed_brand(text, claimed_brand)
    url_results = []

    for url in urls:
        domain = normalize_domain(url)

        age_score, age_findings, age_days = domain_age_verification(domain)
        hosting_score, hosting_findings, origin_data = hosting_origin_consistency_analysis(
            domain, detected_brand
        )
        brand_score, brand_findings = brand_domain_consistency_check(url, detected_brand)

        url_total = age_score + hosting_score + brand_score
        overall_score += url_total

        reasons.extend(age_findings)
        reasons.extend(hosting_findings)
        reasons.extend(brand_findings)

        url_results.append({
            "url": url,
            "domain": domain,
            "domainAgeDays": age_days,
            "hostingOrigin": origin_data,
            "domainAgeScore": age_score,
            "hostingOriginScore": hosting_score,
            "brandDomainScore": brand_score,
            "domainAgeFindings": age_findings,
            "hostingOriginFindings": hosting_findings,
            "brandDomainFindings": brand_findings,
            "totalUrlScore": url_total,
        })

    if not urls:
        reasons.append("No URL found in the message, so identity-based URL checks were not applied")

    overall_score = min(overall_score, 100)

    if overall_score >= 70:
        status = "Suspicious"
        risk_level = "High"
    elif overall_score >= 35:
        status = "Suspicious"
        risk_level = "Medium"
    else:
        status = "Safe"
        risk_level = "Low"

    return {
        "status": status,
        "riskLevel": risk_level,
        "riskScore": overall_score,
        "claimedBrand": detected_brand,
        "messageAnalysis": {
            "bertFindings": bert_findings,
            "bertScore": bert_score,
            "bertPhishingProbability": bert_probability,
        },
        "urlAnalyses": url_results,
        "reasons": reasons,
    }


@app.route("/", methods=["GET"])
def home():
    return "MsgGuard backend works with BERT and identity checks"


@app.route("/analyze", methods=["GET", "POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    if request.method == "GET":
        text = str(request.args.get("text", "")).strip()
        claimed_brand = str(request.args.get("claimedBrand", "")).strip()

        if not text:
            return jsonify({"error": "Input text cannot be empty"}), 400

        result = analyze_input(text, claimed_brand)
        return jsonify(result)

    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    text = str(data.get("text", "")).strip()
    claimed_brand = str(data.get("claimedBrand", "")).strip()

    if not text:
        return jsonify({"error": "Input text cannot be empty"}), 400

    result = analyze_input(text, claimed_brand)
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)