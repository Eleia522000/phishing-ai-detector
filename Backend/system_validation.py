# -*- coding: utf-8 -*-
"""
MsgGuard Full System Validation Script

Purpose:
This script validates the complete MsgGuard backend system, not only the BERT model.

It checks:
1. Backend availability
2. / endpoint status
3. /analyze API behavior
4. Empty input validation
5. Legitimate messages
6. Suspicious messages
7. Phishing messages
8. Trusted official URLs
9. Fake / homoglyph URLs
10. Multiple URLs
11. Multilingual robustness
12. Security edge cases
13. Required response fields
14. Risk score range
15. URL analysis structure
16. MongoDB logging check, if .env and pymongo are available
17. CSV + TXT report generation

How to run:
1. Start backend:
   python msgguard.py

2. Run this script:
   python full_system_validation.py

Install dependencies if needed:
   python -m pip install requests tabulate python-dotenv pymongo
"""

import csv
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from tabulate import tabulate

try:
    from dotenv import load_dotenv
    from pymongo import MongoClient
except Exception:
    load_dotenv = None
    MongoClient = None


API_BASE_URL = "http://127.0.0.1:5000"
ANALYZE_URL = f"{API_BASE_URL}/analyze"

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "full_system_validation_results"
REPORT_DIR.mkdir(exist_ok=True)

CSV_REPORT = REPORT_DIR / "full_system_validation_report.csv"
TXT_REPORT = REPORT_DIR / "full_system_validation_report.txt"


TEST_CASES: List[Dict[str, Any]] = [
    # ---------------------------
    # Legitimate / safe cases
    # ---------------------------
    {
        "category": "Legitimate",
        "name": "Official Microsoft Meeting",
        "text": "Hi Enab, our project meeting is tomorrow at 10:00 AM. Join using the official Teams link: https://teams.microsoft.com",
        "expected": ["Legitimate", "Safe"],
        "requires_url_analysis": True,
    },
    {
        "category": "Legitimate",
        "name": "Official Amazon Order",
        "text": "Your Amazon order has been shipped. You can track it here: https://amazon.com/orders",
        "expected": ["Legitimate", "Safe"],
        "requires_url_analysis": True,
    },
    {
        "category": "Legitimate",
        "name": "Trusted Google URL Only",
        "text": "https://google.com",
        "expected": ["Legitimate", "Safe"],
        "requires_url_analysis": True,
    },
    {
        "category": "Legitimate",
        "name": "Normal Work Message",
        "text": "Hello team, the maintenance window is scheduled for Friday at 09:00. Please review the documentation before deployment.",
        "expected": ["Legitimate", "Safe"],
        "requires_url_analysis": False,
    },

    # ---------------------------
    # Suspicious / phishing wording
    # ---------------------------
    {
        "category": "Suspicious Wording",
        "name": "Unusual Activity No URL",
        "text": "Hello, we noticed unusual activity on your account. Please review your recent login activity as soon as possible.",
        "expected": ["Suspicious", "Phishing"],
        "requires_url_analysis": False,
    },
    {
        "category": "Phishing Wording",
        "name": "Account Locked No URL",
        "text": "Your bank account has been locked due to suspicious activity. Update your information immediately to avoid permanent suspension.",
        "expected": ["Suspicious", "Phishing"],
        "requires_url_analysis": False,
    },

    # ---------------------------
    # Clear phishing / brand impersonation
    # ---------------------------
    {
        "category": "Brand Impersonation",
        "name": "Microsoft Homoglyph",
        "text": "URGENT: Your Microsoft account has been suspended. Verify immediately: https://micr0soft-security-center.com/account/verify",
        "expected": ["Phishing"],
        "requires_url_analysis": True,
        "min_risk_score": 70,
    },
    {
        "category": "Brand Impersonation",
        "name": "PayPal Homoglyph",
        "text": "Your PayPal account is limited. Verify your identity now: http://paypa1-login-security.xyz",
        "expected": ["Phishing", "Suspicious"],
        "requires_url_analysis": True,
        "min_risk_score": 60,
    },
    {
        "category": "Brand Impersonation",
        "name": "Amazon Homoglyph",
        "text": "Your Amazon payment failed. Update your billing details here: http://amaz0n-billing-update.xyz",
        "expected": ["Phishing", "Suspicious"],
        "requires_url_analysis": True,
        "min_risk_score": 60,
    },
    {
        "category": "Brand Impersonation",
        "name": "Google Homoglyph",
        "text": "Google security alert. Review your account here: http://g00gle-login-security.net",
        "expected": ["Phishing", "Suspicious"],
        "requires_url_analysis": True,
        "min_risk_score": 60,
    },

    # ---------------------------
    # URL analysis cases
    # ---------------------------
    {
        "category": "URL Analysis",
        "name": "Unknown Suspicious URL",
        "text": "Please update your billing details here: https://secure-account-update-login.xyz",
        "expected": ["Suspicious", "Phishing"],
        "requires_url_analysis": True,
    },
    {
        "category": "URL Analysis",
        "name": "Multiple URLs Mixed",
        "text": "Official link: https://google.com\nVerification link: http://g00gle-login-security.xyz",
        "expected": ["Suspicious", "Phishing"],
        "requires_url_analysis": True,
        "min_url_count": 2,
    },
    {
        "category": "URL Analysis",
        "name": "Misleading Subdomain",
        "text": "PayPal verification required: http://paypal.login-security-check.com",
        "expected": ["Suspicious", "Phishing"],
        "requires_url_analysis": True,
    },

    # ---------------------------
    # Multilingual robustness
    # ---------------------------
    {
        "category": "Multilingual",
        "name": "Hebrew Message",
        "text": "לחץ כאן כדי לעדכן את החשבון שלך מיד",
        "expected": ["Legitimate", "Suspicious", "Phishing"],
        "requires_url_analysis": False,
    },
    {
        "category": "Multilingual",
        "name": "Arabic Message",
        "text": "اضغط هنا لتحديث حسابك فوراً",
        "expected": ["Legitimate", "Suspicious", "Phishing"],
        "requires_url_analysis": False,
    },

    # ---------------------------
    # Edge/security cases
    # ---------------------------
    {
        "category": "Input Validation",
        "name": "Empty Input",
        "text": "",
        "expected": ["HTTP_400"],
        "expect_http_status": 400,
    },
    {
        "category": "Input Validation",
        "name": "Spaces Only",
        "text": "      ",
        "expected": ["HTTP_400"],
        "expect_http_status": 400,
    },
    {
        "category": "Security Robustness",
        "name": "XSS Input",
        "text": "<script>alert('XSS')</script>",
        "expected": ["Legitimate", "Suspicious", "Phishing"],
        "requires_url_analysis": False,
    },
    {
        "category": "Security Robustness",
        "name": "SQL Injection Input",
        "text": "' OR 1=1 --",
        "expected": ["Legitimate", "Suspicious", "Phishing"],
        "requires_url_analysis": False,
    },
    {
        "category": "Edge Case",
        "name": "Very Long Normal Message",
        "text": "Hello, this is a normal internal update about the project. " * 250,
        "expected": ["Legitimate", "Suspicious"],
        "requires_url_analysis": False,
    },
]


REQUIRED_RESPONSE_FIELDS = [
    "status",
    "riskLevel",
    "riskScore",
    "hasUrls",
    "messageAnalysis",
    "scoreBreakdown",
    "urlAnalyses",
    "reasons",
]


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def check_backend_home() -> Dict[str, Any]:
    start = time.time()
    try:
        response = requests.get(API_BASE_URL, timeout=10)
        elapsed = time.time() - start
        return {
            "name": "Backend Home Endpoint",
            "passed": response.status_code == 200,
            "status": response.status_code,
            "time": elapsed,
            "details": response.text[:150],
        }
    except Exception as exc:
        return {
            "name": "Backend Home Endpoint",
            "passed": False,
            "status": "ERROR",
            "time": time.time() - start,
            "details": str(exc),
        }


def get_mongo_collection():
    if load_dotenv is None or MongoClient is None:
        return None

    load_dotenv()

    mongo_uri = os.getenv("MONGO_URI")
    db_name = os.getenv("MONGO_DB_NAME", "phishing_ai_detector_db")
    collection_name = os.getenv("MONGO_COLLECTION_NAME", "analysis_logs")

    if not mongo_uri:
        return None

    try:
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        return client[db_name][collection_name]
    except Exception:
        return None


def validate_response_schema(data: Dict[str, Any], requires_url_analysis: bool, min_url_count: int = 0) -> List[str]:
    errors = []

    for field in REQUIRED_RESPONSE_FIELDS:
        if field not in data:
            errors.append(f"Missing field: {field}")

    risk_score = data.get("riskScore")
    if not isinstance(risk_score, (int, float)):
        errors.append("riskScore is not numeric")
    elif not (0 <= risk_score <= 100):
        errors.append("riskScore is outside 0-100")

    reasons = data.get("reasons")
    if not isinstance(reasons, list):
        errors.append("reasons is not a list")
    elif len(reasons) == 0:
        errors.append("reasons is empty")

    url_analyses = data.get("urlAnalyses")
    if not isinstance(url_analyses, list):
        errors.append("urlAnalyses is not a list")
    else:
        if requires_url_analysis and len(url_analyses) == 0:
            errors.append("URL analysis required but urlAnalyses is empty")

        if min_url_count and len(url_analyses) < min_url_count:
            errors.append(f"Expected at least {min_url_count} URL analyses, got {len(url_analyses)}")

        for index, item in enumerate(url_analyses):
            for field in ["url", "domain", "domainAgeScore", "hostingOriginScore", "brandDomainScore", "totalUrlScore"]:
                if field not in item:
                    errors.append(f"urlAnalyses[{index}] missing field: {field}")

    return errors


def run_test_case(test: Dict[str, Any], mongo_collection=None) -> Dict[str, Any]:
    start_count = None
    if mongo_collection is not None and test.get("expect_http_status") != 400:
        try:
            start_count = mongo_collection.count_documents({})
        except Exception:
            start_count = None

    start = time.time()

    try:
        response = requests.post(
            ANALYZE_URL,
            json={"text": test["text"], "claimedBrand": ""},
            timeout=45,
        )
        elapsed = time.time() - start

        expected_http_status = test.get("expect_http_status", 200)

        result: Dict[str, Any] = {
            "category": test["category"],
            "test": test["name"],
            "expected": ", ".join(test["expected"]),
            "actual": "",
            "http_status": response.status_code,
            "risk_score": "",
            "risk_level": "",
            "time": round(elapsed, 3),
            "passed": False,
            "errors": [],
            "mongo_logged": "N/A",
        }

        if response.status_code != expected_http_status:
            result["errors"].append(f"Expected HTTP {expected_http_status}, got HTTP {response.status_code}")
            result["actual"] = f"HTTP {response.status_code}"
            return result

        if expected_http_status == 400:
            data = response.json() if "application/json" in response.headers.get("content-type", "") else {}
            result["actual"] = "HTTP_400"
            result["passed"] = "error" in data or "message" in data
            if not result["passed"]:
                result["errors"].append("HTTP 400 response does not contain error/message")
            return result

        data = response.json()
        status = str(data.get("status", "Unknown"))
        result["actual"] = status
        result["risk_score"] = data.get("riskScore", "")
        result["risk_level"] = data.get("riskLevel", "")

        schema_errors = validate_response_schema(
            data,
            requires_url_analysis=test.get("requires_url_analysis", False),
            min_url_count=test.get("min_url_count", 0),
        )
        result["errors"].extend(schema_errors)

        expected_values = [value.lower() for value in test["expected"]]
        if status.lower() not in expected_values:
            result["errors"].append(f"Expected status in {test['expected']}, got {status}")

        min_risk_score = test.get("min_risk_score")
        if min_risk_score is not None:
            risk_score = data.get("riskScore")
            if not isinstance(risk_score, (int, float)) or risk_score < min_risk_score:
                result["errors"].append(f"Expected riskScore >= {min_risk_score}, got {risk_score}")

        if mongo_collection is not None and start_count is not None:
            time.sleep(0.2)
            try:
                end_count = mongo_collection.count_documents({})
                result["mongo_logged"] = "PASS" if end_count > start_count else "FAIL"
                if end_count <= start_count:
                    result["errors"].append("MongoDB log was not created")
            except Exception:
                result["mongo_logged"] = "ERROR"

        result["passed"] = len(result["errors"]) == 0
        return result

    except Exception as exc:
        return {
            "category": test["category"],
            "test": test["name"],
            "expected": ", ".join(test["expected"]),
            "actual": "EXCEPTION",
            "http_status": "ERROR",
            "risk_score": "",
            "risk_level": "",
            "time": round(time.time() - start, 3),
            "passed": False,
            "errors": [str(exc)],
            "mongo_logged": "N/A",
        }


def save_reports(rows: List[Dict[str, Any]], home_result: Dict[str, Any]) -> None:
    fieldnames = [
        "category",
        "test",
        "expected",
        "actual",
        "http_status",
        "risk_score",
        "risk_level",
        "time",
        "mongo_logged",
        "passed",
        "errors",
    ]

    with CSV_REPORT.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            row_copy = dict(row)
            row_copy["errors"] = " | ".join(row_copy.get("errors", []))
            writer.writerow(row_copy)

    passed = sum(1 for row in rows if row["passed"])
    failed = len(rows) - passed
    times = [row["time"] for row in rows if isinstance(row["time"], (int, float))]

    category_summary = {}
    for row in rows:
        category = row["category"]
        category_summary.setdefault(category, {"passed": 0, "total": 0})
        category_summary[category]["total"] += 1
        if row["passed"]:
            category_summary[category]["passed"] += 1

    with TXT_REPORT.open("w", encoding="utf-8") as f:
        f.write("MsgGuard Full System Validation Report\n")
        f.write("=" * 60 + "\n\n")

        f.write("Backend Health\n")
        f.write("-" * 30 + "\n")
        f.write(f"Home endpoint passed: {home_result['passed']}\n")
        f.write(f"HTTP status: {home_result['status']}\n")
        f.write(f"Response time: {home_result['time']:.3f}s\n")
        f.write(f"Details: {home_result['details']}\n\n")

        f.write("Summary\n")
        f.write("-" * 30 + "\n")
        f.write(f"Total tests: {len(rows)}\n")
        f.write(f"Passed: {passed}\n")
        f.write(f"Failed: {failed}\n")
        f.write(f"Success rate: {(passed / len(rows)) * 100:.2f}%\n")
        f.write(f"Average response time: {sum(times) / len(times):.3f}s\n")
        f.write(f"Minimum response time: {min(times):.3f}s\n")
        f.write(f"Maximum response time: {max(times):.3f}s\n\n")

        f.write("Category Summary\n")
        f.write("-" * 30 + "\n")
        for category, values in sorted(category_summary.items()):
            f.write(f"{category}: {values['passed']}/{values['total']} passed\n")

        f.write("\nDetailed Results\n")
        f.write("-" * 30 + "\n")
        for row in rows:
            f.write(
                f"[{'PASS' if row['passed'] else 'FAIL'}] "
                f"{row['category']} - {row['test']} | "
                f"Expected: {row['expected']} | Actual: {row['actual']} | "
                f"Risk: {row['risk_score']} | HTTP: {row['http_status']} | "
                f"Mongo: {row['mongo_logged']} | Time: {row['time']}s\n"
            )
            if row["errors"]:
                f.write(f"    Errors: {' | '.join(row['errors'])}\n")


def main() -> None:
    print("=" * 90)
    print("MSGGUARD FULL SYSTEM VALIDATION")
    print("=" * 90)

    home_result = check_backend_home()
    print(f"Backend home endpoint: {'PASS' if home_result['passed'] else 'FAIL'}")
    print(f"Status: {home_result['status']} | Time: {home_result['time']:.3f}s")

    mongo_collection = get_mongo_collection()
    if mongo_collection is None:
        print("MongoDB logging check: SKIPPED (.env/pymongo/connection not available)")
    else:
        print("MongoDB logging check: ENABLED")

    print("-" * 90)

    rows = []
    for test in TEST_CASES:
        result = run_test_case(test, mongo_collection)
        rows.append(result)

        print(
            f"[{'PASS' if result['passed'] else 'FAIL'}] "
            f"{result['category']} | {result['test']} | "
            f"Actual: {result['actual']} | Risk: {result['risk_score']} | "
            f"HTTP: {result['http_status']} | Mongo: {result['mongo_logged']} | "
            f"Time: {result['time']}s"
        )

        if result["errors"]:
            print(f"    Errors: {' | '.join(result['errors'])}")

    save_reports(rows, home_result)

    passed = sum(1 for row in rows if row["passed"])
    failed = len(rows) - passed
    times = [row["time"] for row in rows if isinstance(row["time"], (int, float))]

    summary_table = [
        ["Backend home", "PASS" if home_result["passed"] else "FAIL"],
        ["MongoDB check", "ENABLED" if mongo_collection is not None else "SKIPPED"],
        ["Total tests", len(rows)],
        ["Passed", passed],
        ["Failed", failed],
        ["Success rate", f"{(passed / len(rows)) * 100:.2f}%"],
        ["Average response time", f"{sum(times) / len(times):.3f}s"],
        ["CSV report", str(CSV_REPORT)],
        ["TXT report", str(TXT_REPORT)],
    ]

    print("\n" + "=" * 90)
    print("SUMMARY")
    print("=" * 90)
    print(tabulate(summary_table, tablefmt="grid"))


if __name__ == "__main__":
    main()

