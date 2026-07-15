"""Domain registration, DNS, and hosting-origin analysis."""

import socket
from datetime import datetime, timezone

import requests
import tldextract
import whois

from Backend.config import EXPECTED_BRAND_REGIONS
from Backend.analyzers.url_analyzer import (
    is_trusted_official_domain,
    normalize_domain,
)
from Backend.utils.helpers import dedupe_keep_order


def parse_domain_date(date_value):
    """Convert RDAP or WHOIS date values into a timezone-aware datetime."""
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
            parsed_date = datetime.fromisoformat(clean_date.replace("Z", "+00:00"))
            if parsed_date.tzinfo is None:
                parsed_date = parsed_date.replace(tzinfo=timezone.utc)
            return parsed_date
        except Exception as exc:
            print("Date parsing failed:", repr(exc))
            print("Raw date value:", clean_date)
            return None

    return None


def extract_rdap_registrar(data: dict):
    """Extract the registrar name from an RDAP response when available."""
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
    except Exception as exc:
        print("RDAP registrar parsing failed:", repr(exc))

    return None


def safe_get_whois_info(domain: str) -> dict:
    """Retrieve registration information using RDAP first and WHOIS as fallback."""
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

    rdap_urls = [f"https://rdap.org/domain/{domain}"]
    extracted_domain = tldextract.extract(domain)
    suffix = (extracted_domain.suffix or "").lower()

    if suffix in ["com", "net"]:
        rdap_urls.append(f"https://rdap.verisign.com/{suffix}/v1/domain/{domain}")
    elif suffix == "org":
        rdap_urls.append(
            f"https://rdap.publicinterestregistry.org/rdap/domain/{domain}"
        )

    for rdap_url in dedupe_keep_order(rdap_urls):
        try:
            print("RDAP lookup:", rdap_url)
            response = requests.get(
                rdap_url,
                timeout=10,
                headers={"Accept": "application/rdap+json, application/json"},
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
                    elif event_action in [
                        "last changed",
                        "last update of rdap database",
                        "last update",
                    ]:
                        updated_date = parse_domain_date(event_date)

                registrar = extract_rdap_registrar(data)
                status_values = data.get("status", None)

                if creation_date:
                    info["available"] = True
                    info["source"] = "RDAP"
                    info["creationDate"] = creation_date.isoformat()
                    info["registrar"] = registrar
                    info["expirationDate"] = (
                        expiration_date.isoformat() if expiration_date else None
                    )
                    info["updatedDate"] = (
                        updated_date.isoformat() if updated_date else None
                    )
                    info["rawStatus"] = status_values
                    print("RDAP creation date found:", info["creationDate"])
                    return info

                info["error"] = "RDAP worked, but no registration event was found"
                print(info["error"])
            else:
                info["error"] = (
                    f"RDAP HTTP {response.status_code}: {response.text[:200]}"
                )
                print(info["error"])
        except Exception as exc:
            info["error"] = f"RDAP failed: {repr(exc)}"
            print(info["error"])

    try:
        print("Trying WHOIS for:", domain)

        if not hasattr(whois, "whois"):
            info["error"] = (
                "Installed whois module has no whois() function. "
                "Install python-whois or rely on RDAP."
            )
            print(info["error"])
            return info

        whois_result = whois.whois(domain)
        creation_date = parse_domain_date(
            getattr(whois_result, "creation_date", None)
        )
        expiration_date = parse_domain_date(
            getattr(whois_result, "expiration_date", None)
        )
        updated_date = parse_domain_date(
            getattr(whois_result, "updated_date", None)
        )

        print(
            "WHOIS creation_date raw:",
            getattr(whois_result, "creation_date", None),
        )

        if creation_date:
            info["available"] = True
            info["source"] = "WHOIS"
            info["creationDate"] = creation_date.isoformat()
            info["registrar"] = getattr(whois_result, "registrar", None)
            info["expirationDate"] = (
                expiration_date.isoformat() if expiration_date else None
            )
            info["updatedDate"] = (
                updated_date.isoformat() if updated_date else None
            )
            info["rawStatus"] = getattr(whois_result, "status", None)
            print("WHOIS creation date found:", info["creationDate"])
            return info

        info["error"] = "WHOIS returned no creation date"
        print(info["error"])
    except Exception as exc:
        info["error"] = f"WHOIS failed: {repr(exc)}"
        print(info["error"])

    print("Could not retrieve creation date for:", domain)
    return info


def safe_get_creation_date(domain: str):
    """Return only the parsed domain creation date, or None."""
    whois_info = safe_get_whois_info(domain)
    creation_date_value = whois_info.get("creationDate")

    if not creation_date_value:
        return None

    return parse_domain_date(creation_date_value)


def compute_domain_age_days(domain: str):
    """Return domain age in days, or None when unavailable."""
    creation_date = safe_get_creation_date(domain)

    if not creation_date:
        return None

    now = datetime.now(timezone.utc)
    age_days = (now - creation_date).days
    print("Domain age days:", age_days)
    return age_days


def domain_age_verification(domain: str):
    """Score the domain according to its registration age."""
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
        findings.append(
            f"Registration lookup source: {whois_info.get('source')}"
        )

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


def resolve_ip(domain: str):
    """Resolve a domain to an IPv4 address."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def lookup_hosting_origin(ip_address: str):
    """Retrieve hosting-origin information from ipwho.is."""
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
    except Exception as exc:
        print("Hosting-origin lookup failed:", repr(exc))

    return None


def hosting_origin_consistency_analysis(domain: str, brand):
    """Compare hosting location with the expected regions of a detected brand."""
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
    elif not ip_address:
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

    if is_trusted_official_domain(domain):
        findings.append(
            "Hosting-origin mismatch skipped because this is a trusted official domain"
        )
        return score, findings, origin_data

    country_code = origin_data.get("country_code")

    if brand and brand in EXPECTED_BRAND_REGIONS and origin_data.get("available"):
        expected_regions = EXPECTED_BRAND_REGIONS[brand]
        if country_code not in expected_regions:
            score += 15
            findings.append(
                f"Hosting-origin mismatch: expected one of {expected_regions}, "
                f"got {country_code}"
            )
        else:
            findings.append("Hosting origin is consistent with expected brand region")
    elif brand and brand in EXPECTED_BRAND_REGIONS:
        findings.append("Hosting-origin comparison unavailable")
    else:
        findings.append("No claimed brand available for hosting-origin comparison")

    return score, findings, origin_data
