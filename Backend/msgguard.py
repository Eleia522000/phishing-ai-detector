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

print("RUNNING MSGGUARD BACKEND - WHOIS_HOSTING_ALWAYS_VISIBLE_V9")


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


# --------------------------------------------------
# BERT model configuration
# --------------------------------------------------
PROJECT_DIR = Path(__file__).resolve().parent.parent
BERT_MODEL_PATH = PROJECT_DIR / "models" / "bert_model_v4"

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


# --------------------------------------------------
# Brand/domain data
# --------------------------------------------------
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
    "google": ["google.com", "gmail.com", "goo.gl", "google.co.il"],
    "paypal": ["paypal.com", "paypal.me"],
    "amazon": ["amazon.com", "amazon.co.uk"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "bankhapoalim": ["bankhapoalim.co.il"],
    "leumi": ["leumi.co.il"],
    "discount": ["discountbank.co.il"],
    "isracard": ["isracard.co.il"],
    "visa": ["visa.com"],
    "mastercard": ["mastercard.com"],
}

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


SUSPICIOUS_URL_WORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "confirm",
    "identity",
    "update",
    "secure",
    "account",
    "password",
    "session",
    "auth",
    "staffportal",
    "portal",
    "benefits",
    "payroll",
    "salary",
    "document",
    "invoice",
    "payment",
    "billing",
    "support",
    "check",
    "unlock",
    "restore",
    "limited",
    "suspend",
    "suspended",
]

SUSPICIOUS_MESSAGE_WORDS = [
    "urgent",
    "immediately",
    "today",
    "expires",
    "expire",
    "within 24 hours",
    "before the end of the day",
    "account locked",
    "account suspended",
    "temporarily disabled",
    "access may be limited",
    "verify your account",
    "confirm your details",
    "confirm your information",
    "confirm your identity",
    "verify your identity",
    "update your information",
    "password",
    "credentials",
    "payroll",
    "salary",
    "benefits",
    "payment failed",
    "billing details",
    "security alert",
    "login now",
    "act now",
]


# --------------------------------------------------
# General helpers
# --------------------------------------------------
def dedupe_keep_order(items):
    seen = set()
    clean = []

    for item in items:
        if item and item not in seen:
            clean.append(item)
            seen.add(item)

    return clean


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


def is_url_only_input(text, urls):
    """
    True when the user submitted only one URL and no real message context.
    Examples:
    https://google.com
    google.com
    www.google.com
    """
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


def extract_text_without_urls(text, urls):
    """
    Removes extracted URLs from the message so we can check whether
    there is meaningful text context besides the URL.
    """
    clean_text = text or ""

    for url in urls:
        raw_url = url
        no_http = url.replace("http://", "").replace("https://", "")
        no_www = no_http.replace("www.", "")

        for candidate in [raw_url, no_http, no_www]:
            clean_text = clean_text.replace(candidate, " ")

    return re.sub(r"\s+", " ", clean_text).strip()


def contains_high_risk_phishing_language(text):
    """
    Detects strong social-engineering wording that should not be ignored,
    even if no URL exists.
    """
    text_lower = (text or "").lower()

    high_risk_patterns = [
        "urgent",
        "suspended",
        "account suspended",
        "account locked",
        "locked",
        "limited",
        "restricted",
        "verify immediately",
        "verify your account",
        "verify your password",
        "confirm your account",
        "confirm your details",
        "confirm your information",
        "confirm your identity",
        "update your information",
        "update your account",
        "billing details",
        "password",
        "credentials",
        "account closure",
        "will be deleted",
        "failure to comply",
        "claim your prize",
        "free iphone",
        "gift card",
        "bank account",
        "security alert",
        "login now",
        "act now",
    ]

    return any(pattern in text_lower for pattern in high_risk_patterns)


def contains_strong_legitimate_context(text):
    """
    Detects ordinary work/project context that can reduce false positives
    when no suspicious URL identity signals exist.
    """
    text_lower = (text or "").lower()

    legitimate_patterns = [
        "meeting",
        "project",
        "presentation",
        "schedule",
        "server maintenance",
        "maintenance window",
        "tomorrow",
        "best regards",
        "regards",
        "department",
        "official",
        "shared with you",
        "work",
        "team update",
    ]

    return any(pattern in text_lower for pattern in legitimate_patterns)


def is_safe_trusted_url_context(text, urls, url_results):
    """
    Returns True only when every URL belongs to a trusted official domain
    and there is no suspicious brand-domain identity risk.
    """
    if not urls or not url_results:
        return False

    all_trusted = all(item.get("trustedOfficialDomain") is True for item in url_results)
    no_brand_risk = all(item.get("brandDomainScore", 0) == 0 for item in url_results)
    no_structure_risk = all(item.get("urlStructureScore", 0) < 25 for item in url_results)

    if not all_trusted or not no_brand_risk or not no_structure_risk:
        return False

    if contains_high_risk_phishing_language(text):
        return False

    return True


def extract_urls(text):
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?)'
    urls = re.findall(url_pattern, text or "")
    cleaned_urls = []

    for url in urls:
        url = url.rstrip('.,);]>"\'')
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        cleaned_urls.append(url)

    return dedupe_keep_order(cleaned_urls)


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
        "hostname": netloc,
    }


# --------------------------------------------------
# Brand/domain analysis
# --------------------------------------------------
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
    candidates.extend(split_domain_tokens(parts["subdomain"]))
    candidates.extend([normalize_homoglyphs(t) for t in split_domain_tokens(parts["subdomain"])])

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

    return min(score, 60), dedupe_keep_order(findings)


# --------------------------------------------------
# Domain age and hosting analysis
# --------------------------------------------------
def parse_domain_date(date_value):
    """
    Converts RDAP or WHOIS date values into a timezone-aware datetime object.
    Returns None if the date cannot be parsed.
    """
    if not date_value:
        return None

    if isinstance(date_value, list):
        date_value = date_value[0] if date_value else None

    if isinstance(date_value, datetime):
        parsed_date = date_value

        if parsed_date.tzinfo is None:
            parsed_date = parsed_date.replace(tzinfo=timezone.utc)

        return parsed_date

    if isinstance(date_value, str):
        clean_date = date_value.strip()

        try:
            parsed_date = datetime.fromisoformat(
                clean_date.replace("Z", "+00:00")
            )

            if parsed_date.tzinfo is None:
                parsed_date = parsed_date.replace(tzinfo=timezone.utc)

            return parsed_date

        except Exception as e:
            print("Date parsing failed:", repr(e))
            print("Raw date value:", clean_date)
            return None

    return None


def extract_rdap_registrar(data):
    """
    Tries to extract registrar name from RDAP entities.
    Not every RDAP response exposes the registrar in the same shape.
    """
    try:
        for entity in data.get("entities", []):
            roles = [role.lower() for role in entity.get("roles", [])]

            if "registrar" not in roles:
                continue

            vcard = entity.get("vcardArray", [])
            if len(vcard) < 2:
                continue

            for item in vcard[1]:
                if len(item) >= 4 and item[0] == "fn":
                    return item[3]

    except Exception as e:
        print("RDAP registrar parsing failed:", repr(e))

    return None


def safe_get_whois_info(domain):
    """
    Always returns structured domain-registration information.

    1. RDAP first because it returns structured JSON and is more reliable.
    2. WHOIS fallback only if RDAP fails.
    """
    domain = (domain or "").lower().strip()

    info = {
        "available": False,
        "source": None,
        "creationDate": None,
        "registrar": None,
        "expirationDate": None,
        "updatedDate": None,
        "rawStatus": None,
        "error": None,
    }

    if not domain:
        info["error"] = "Empty domain"
        return info

    if domain.startswith("http://") or domain.startswith("https://"):
        domain = normalize_domain(domain)

    print("Checking domain age for:", domain)

    # 1. RDAP lookup.
    # Try rdap.org first, then direct registry RDAP endpoints for common TLDs.
    rdap_urls = [f"https://rdap.org/domain/{domain}"]

    extracted_domain = tldextract.extract(domain)
    suffix = (extracted_domain.suffix or "").lower()

    if suffix in ["com", "net"]:
        rdap_urls.append(f"https://rdap.verisign.com/{suffix}/v1/domain/{domain}")
    elif suffix == "org":
        rdap_urls.append(f"https://rdap.publicinterestregistry.org/rdap/domain/{domain}")

    for rdap_url in dedupe_keep_order(rdap_urls):
        try:
            print("RDAP lookup:", rdap_url)

            response = requests.get(
                rdap_url,
                timeout=10,
                headers={"Accept": "application/rdap+json, application/json"}
            )

            print("RDAP status:", response.status_code)

            if response.status_code == 200:
                data = response.json()

                creation_date = None
                expiration_date = None
                updated_date = None

                for event in data.get("events", []):
                    event_action = (event.get("eventAction") or "").lower().strip()
                    event_date = event.get("eventDate")

                    print("RDAP event:", event_action, event_date)

                    if event_action in ["registration", "registered"]:
                        creation_date = parse_domain_date(event_date)
                    elif event_action in ["expiration", "expiry"]:
                        expiration_date = parse_domain_date(event_date)
                    elif event_action in ["last changed", "last update of rdap database", "last update"]:
                        updated_date = parse_domain_date(event_date)

                registrar = extract_rdap_registrar(data)

                status_values = data.get("status", None)

                if creation_date:
                    info["available"] = True
                    info["source"] = "RDAP"
                    info["creationDate"] = creation_date.isoformat()
                    info["registrar"] = registrar
                    info["expirationDate"] = expiration_date.isoformat() if expiration_date else None
                    info["updatedDate"] = updated_date.isoformat() if updated_date else None
                    info["rawStatus"] = status_values
                    print("RDAP creation date found:", info["creationDate"])
                    return info

                info["error"] = "RDAP worked, but no registration event was found"
                print(info["error"])

            else:
                info["error"] = f"RDAP HTTP {response.status_code}: {response.text[:200]}"
                print(info["error"])

        except Exception as e:
            info["error"] = f"RDAP failed: {repr(e)}"
            print(info["error"])

    # 2. WHOIS fallback
    try:
        print("Trying WHOIS for:", domain)

        if not hasattr(whois, "whois"):
            info["error"] = "Installed whois module has no whois() function. Install python-whois or rely on RDAP."
            print(info["error"])
            return info

        w = whois.whois(domain)

        creation_date = parse_domain_date(getattr(w, "creation_date", None))
        expiration_date = parse_domain_date(getattr(w, "expiration_date", None))
        updated_date = parse_domain_date(getattr(w, "updated_date", None))

        print("WHOIS creation_date raw:", getattr(w, "creation_date", None))

        if creation_date:
            info["available"] = True
            info["source"] = "WHOIS"
            info["creationDate"] = creation_date.isoformat()
            info["registrar"] = getattr(w, "registrar", None)
            info["expirationDate"] = expiration_date.isoformat() if expiration_date else None
            info["updatedDate"] = updated_date.isoformat() if updated_date else None
            info["rawStatus"] = getattr(w, "status", None)
            print("WHOIS creation date found:", info["creationDate"])
            return info

        info["error"] = "WHOIS returned no creation date"
        print(info["error"])

    except Exception as e:
        info["error"] = f"WHOIS failed: {repr(e)}"
        print(info["error"])

    print("Could not retrieve creation date for:", domain)
    return info


def safe_get_creation_date(domain):
    whois_info = safe_get_whois_info(domain)
    creation_date_value = whois_info.get("creationDate")

    if not creation_date_value:
        return None

    return parse_domain_date(creation_date_value)


def compute_domain_age_days(domain):
    creation_date = safe_get_creation_date(domain)

    if not creation_date:
        return None

    now = datetime.now(timezone.utc)
    age_days = (now - creation_date).days

    print("Domain age days:", age_days)

    return age_days


def domain_age_verification(domain):
    score = 0
    findings = []
    whois_info = safe_get_whois_info(domain)

    creation_date_value = whois_info.get("creationDate")
    age_days = None

    if creation_date_value:
        creation_date = parse_domain_date(creation_date_value)

        if creation_date:
            now = datetime.now(timezone.utc)
            age_days = (now - creation_date).days

    if creation_date_value:
        findings.append(f"Domain creation date: {creation_date_value[:10]}")
    else:
        findings.append("Domain creation date: unavailable")

    if whois_info.get("registrar"):
        findings.append(f"Domain registrar: {whois_info.get('registrar')}")
    else:
        findings.append("Domain registrar: unavailable")

    if whois_info.get("source"):
        findings.append(f"Registration lookup source: {whois_info.get('source')}")

    if age_days is None:
        findings.append("Domain age: unavailable")
        return score, findings, None, whois_info

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

    return score, findings, age_days, whois_info


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
    except Exception as e:
        print("Hosting-origin lookup failed:", repr(e))

    return None


def hosting_origin_consistency_analysis(domain, brand):
    score = 0
    findings = []

    ip_address = resolve_ip(domain)

    origin_data = {
        "available": False,
        "ip": ip_address,
        "country_code": None,
        "country": None,
        "region": None,
        "city": None,
        "org": None,
        "error": None,
    }

    raw_origin = lookup_hosting_origin(ip_address)

    if raw_origin:
        origin_data.update(raw_origin)
        origin_data["available"] = True
    else:
        if not ip_address:
            origin_data["error"] = "Could not resolve domain IP address"
        else:
            origin_data["error"] = "Could not retrieve hosting-origin information"

    if origin_data.get("org"):
        findings.append(f"Hosting provider: {origin_data.get('org')}")
    else:
        findings.append("Hosting provider: unavailable")

    if origin_data.get("country") or origin_data.get("country_code"):
        findings.append(
            f"Server location: {origin_data.get('country') or 'Unknown'} "
            f"({origin_data.get('country_code') or 'Unknown'})"
        )
    else:
        findings.append("Server location: unavailable")

    if origin_data.get("ip"):
        findings.append(f"Resolved IP address: {origin_data.get('ip')}")
    else:
        findings.append("Resolved IP address: unavailable")

    # Do not flag hosting-region mismatch for official trusted domains.
    # Large services use CDN and local edge servers, so google.com may resolve in Israel.
    if is_trusted_official_domain(domain):
        findings.append("Hosting-origin mismatch skipped because this is a trusted official domain")
        return score, findings, origin_data

    country_code = origin_data.get("country_code")

    if brand and brand in EXPECTED_BRAND_REGIONS and origin_data.get("available"):
        expected_regions = EXPECTED_BRAND_REGIONS[brand]
        if country_code not in expected_regions:
            score += 15
            findings.append(
                f"Hosting-origin mismatch: expected one of {expected_regions}, got {country_code}"
            )
        else:
            findings.append("Hosting origin is consistent with expected brand region")
    elif brand and brand in EXPECTED_BRAND_REGIONS:
        findings.append("Hosting-origin comparison unavailable")
    else:
        findings.append("No claimed brand available for hosting-origin comparison")

    return score, findings, origin_data


# --------------------------------------------------
# Message and URL structure analysis
# --------------------------------------------------
def analyze_message_wording(text):
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

    if any(word in text_lower for word in ["expires", "expire", "today", "end of the day", "limited"]):
        score += 15
        findings.append("Message creates urgency or pressure to act quickly")

    if any(word in text_lower for word in ["confirm", "verify", "identity", "details", "information"]):
        score += 15
        findings.append("Message asks the user to confirm or verify personal/account information")

    if any(word in text_lower for word in ["password", "credentials", "payroll", "salary", "benefits", "bank account"]):
        score += 10
        findings.append("Message refers to sensitive account, payroll, or credential information")

    return min(score, 65), dedupe_keep_order(findings)


def analyze_url_structure(url):
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
            "URL contains phishing-related words: "
            + ", ".join(found_words)
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

    if any(word in path for word in ["login", "verify", "confirm", "identity", "auth", "session"]):
        score += 20
        findings.append("URL path looks like login, verification, or identity-confirmation flow")

    # Official trusted domains can contain words such as login or account in a normal path.
    # Reduce only the structure score, not brand mismatch signals.
    if is_trusted_official_domain(registered_domain):
        score = max(0, score - 40)
        findings.append("Registered domain is in the trusted official domain list")

    return min(score, 75), dedupe_keep_order(findings)


# --------------------------------------------------
# BERT model scoring
# --------------------------------------------------
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

        # Keep BERT as one signal. It should not be the only decision maker.
        score = int(phishing_probability * 50)

        findings = [f"BERT phishing probability: {phishing_probability:.2%}"]

        if phishing_probability >= 0.80:
            findings.append("High-risk phishing pattern detected by BERT model")
        elif phishing_probability >= 0.50:
            findings.append("Moderate phishing pattern detected by BERT model")
        else:
            findings.append("Low phishing probability according to BERT model")

        return score, dedupe_keep_order(findings), phishing_probability

    except Exception as e:
        return 0, [f"BERT model could not analyze input: {str(e)}"], None


# --------------------------------------------------
# Main analyzer
# --------------------------------------------------
def analyze_input(text, claimed_brand=None):
    urls = extract_urls(text)
    url_results = []
    reasons = []

    # URL-only input should be judged by URL analysis, not by the BERT text classifier.
    # Example: https://secure-login.example.com
    # BERT may overreact to words like login/verify/account inside a URL.
    url_only_input = is_url_only_input(text, urls)

    if url_only_input:
        bert_score = 0
        bert_findings = []
        bert_probability = None

        # There is no real message wording in URL-only input.
        # Do not score URL words twice as message wording.
        wording_score = 0
        wording_findings = []

        reasons.append("URL-only input detected; BERT text classification was skipped and URL analysis was used instead")
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

        # If the message did not mention a brand, infer it from suspicious URL similarity.
        url_brand = detected_brand or detect_brand_from_url(url)

        age_score, age_findings, age_days, whois_info = domain_age_verification(domain)

        hosting_score, hosting_findings, origin_data = hosting_origin_consistency_analysis(
            domain,
            url_brand
        )

        brand_score, brand_findings = brand_domain_consistency_check(url, url_brand)

        structure_score, structure_findings = analyze_url_structure(url)

        total_domain_age_score += age_score
        total_hosting_score += hosting_score
        total_brand_score += brand_score

        url_total_score = min(
            age_score + hosting_score + brand_score + structure_score,
            100
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

    # Use the highest URL score, not a weak average.
    # One suspicious URL should be enough to raise the full message risk.
    url_score = min(highest_url_score, 80)

    # Strongest-signal scoring.
    # For URL-only input, do not let BERT or message-wording logic decide.
    # The URL analyzer is the source of truth.
    if url_only_input:
        overall_score = url_score
    else:
        overall_score = max(
            bert_score,
            wording_score,
            url_score
        )

    # Combination escalation:
    # Suspicious wording + suspicious URL = higher risk.
    if wording_score >= 25 and url_score >= 35:
        overall_score = max(overall_score, min(url_score + 15, 90))
        reasons.append("Escalation applied: suspicious message wording combined with suspicious URL structure")

    # Brand/domain escalation.
    if total_brand_score >= 35:
        overall_score = max(overall_score, 70)
        reasons.append("Escalation applied: suspicious brand-domain mismatch detected")

    # BERT + URL escalation.
    if bert_probability is not None and bert_probability >= 0.80 and url_score >= 30:
        overall_score = max(overall_score, 75)
        reasons.append("Escalation applied: high BERT phishing probability combined with suspicious URL signals")

    # Text-only phishing escalation.
    if (
        not urls
        and bert_probability is not None
        and bert_probability >= 0.80
        and contains_high_risk_phishing_language(text)
    ):
        overall_score = max(overall_score, 70)
        reasons.append("Escalation applied: high-risk phishing wording without URL")

    trusted_safe_context = is_safe_trusted_url_context(text, urls, url_results)

    # Only force score to zero for URL-only official trusted domains.
    # Example: https://google.com
    if trusted_safe_context and is_url_only_input(text, urls):
        overall_score = 0
        reasons.append("Trusted official URL-only input detected with no suspicious identity signals")

    # Trusted official domains with normal work/project context can reduce score,
    # but they should not erase strong phishing wording.
    if trusted_safe_context and not is_url_only_input(text, urls):
        context_text = extract_text_without_urls(text, urls)

        if contains_strong_legitimate_context(context_text) and wording_score < 25:
            overall_score = max(0, overall_score - 25)
            reasons.append("Trusted official domain detected with safe message context")

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

    message_findings = dedupe_keep_order(
        bert_findings + wording_findings
    )

    link_findings = []

    for item in url_results:
        link_findings.append(f"URL: {item.get('url')}")
        link_findings.append(f"Domain: {item.get('domain')}")

        link_findings.extend(item.get("urlStructureFindings", []))
        link_findings.extend(item.get("brandDomainFindings", []))

        # Always display WHOIS / creation date / hosting origin information.
        whois_info = item.get("whoisInfo") or {}
        creation_date = item.get("domainCreationDate")

        if creation_date:
            link_findings.append(f"Domain creation date: {creation_date[:10]}")
        else:
            link_findings.append("Domain creation date: unavailable")

        if item.get("domainAgeDays") is not None:
            link_findings.append(f"Domain age: {item.get('domainAgeDays')} days")
        else:
            link_findings.append("Domain age: unavailable")

        if whois_info.get("registrar"):
            link_findings.append(f"WHOIS registrar: {whois_info.get('registrar')}")
        else:
            link_findings.append("WHOIS registrar: unavailable")

        hosting = item.get("hostingOrigin") or {}
        provider = hosting.get("org") or "unavailable"
        country = hosting.get("country") or "unavailable"
        country_code = hosting.get("country_code") or "unavailable"
        ip_address = hosting.get("ip") or "unavailable"

        link_findings.append(f"Hosting provider: {provider}")
        link_findings.append(f"Server location: {country} ({country_code})")
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
            # Use this one in the frontend to avoid duplicates.
            "findings": message_findings,

            # These are separate categories for optional detailed display.
            "bertFindings": bert_findings,
            "wordingFindings": wording_findings,

            "score": max(bert_score, wording_score),
            "confidence": bert_probability,
            "bertScore": bert_score,
            "bertPhishingProbability": bert_probability,
            "wordingScore": wording_score,
            "modelInputType": "url_only" if url_only_input else "message_and_url_text",
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

        # Use these in summary screens.
        "reasons": unique_reasons,
        "findings": unique_reasons,
        "topReasons": unique_reasons[:5],
    }


# --------------------------------------------------
# Database logging
# --------------------------------------------------
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


# --------------------------------------------------
# Routes
# --------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    return "MsgGuard backend works with BERT, message analysis, homoglyph detection, URL structure checks, and URL identity checks"


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "message": "MsgGuard backend is running",
        "bertAvailable": BERT_AVAILABLE,
        "mongoLoggingEnabled": mongo_collection is not None,
    })


@app.route("/analyze", methods=["GET", "POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    if request.method == "GET":
        text = str(request.args.get("text", "")).strip()
        claimed_brand = (request.args.get("claimedBrand") or "").strip() or None

        if not text:
            return jsonify({
                "success": False,
                "error": "Input text cannot be empty",
                "message": "Please enter a message before analyzing."
            }), 400

        start_time = time.time()
        result = analyze_input(text, claimed_brand)
        response_time = time.time() - start_time

        result["success"] = True
        result["responseTime"] = response_time
        save_analysis_to_db(text, result, response_time)

        return jsonify(result)

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "error": "Missing JSON body",
            "message": "Please enter a message before analyzing."
        }), 400

    # Supports both frontend key names: "text" and "message".
    text = str(data.get("text") or data.get("message") or "").strip()
    claimed_brand = (data.get("claimedBrand") or "").strip() or None

    if not text:
        return jsonify({
            "success": False,
            "error": "Input text cannot be empty",
            "message": "Please enter a message before analyzing."
        }), 400

    start_time = time.time()
    result = analyze_input(text, claimed_brand)
    response_time = time.time() - start_time

    result["success"] = True
    result["responseTime"] = response_time
    save_analysis_to_db(text, result, response_time)

    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)


