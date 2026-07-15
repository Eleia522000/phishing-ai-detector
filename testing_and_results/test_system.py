# -*- coding: utf-8 -*-
"""
Created on Tue May 26 08:52:42 2026

@author: enabf
"""

import requests
import time

BACKEND_URL = "http://127.0.0.1:5000/analyze"

test_cases = [
    {
        "name": "Legitimate Teams Meeting",
        "text": "Hi, the meeting moved to 14:30. Join: https://teams.microsoft.com",
        "expected": ["Legitimate", "Safe"],
    },
    {
        "name": "Legitimate Amazon",
        "text": "Track your order: https://amazon.com/orders",
        "expected": ["Legitimate", "Safe"],
    },
    {
        "name": "Phishing Wording Only",
        "text": "URGENT: Your mailbox will be deleted today. Send your verification code immediately.",
        "expected": ["Suspicious", "Phishing"],
    },
    {
        "name": "Amazon Homoglyph",
        "text": "Your Amazon package failed. Track: http://amaz0n-delivery-check.com",
        "expected": ["Phishing"],
    },
    {
        "name": "PayPal Homoglyph",
        "text": "Your PayPal account is limited. Verify: http://paypa1-security-login.xyz",
        "expected": ["Phishing"],
    },
    {
        "name": "Google Homoglyph",
        "text": "Google alert. Review: http://g00gle-authentication-check.net",
        "expected": ["Phishing"],
    },
    {
        "name": "Misleading Microsoft Subdomain",
        "text": "Microsoft security warning: http://microsoft.login-security-check.com",
        "expected": ["Suspicious", "Phishing"],
    },
    {
        "name": "Fake Bank Hapoalim",
        "text": "Bank Hapoalim alert: login now http://bankhapoalim-secure-login.com",
        "expected": ["Phishing"],
    },
    {
        "name": "Apple Fake Support",
        "text": "Apple ID locked. Confirm: https://appleid-verification-support.com/login",
        "expected": ["Phishing"],
    },
    {
        "name": "Legitimate Text Only",
        "text": "Hi, can you send me the project file before tomorrow? Thanks.",
        "expected": ["Legitimate", "Safe"],
    },
]

passed = 0
failed = 0
times = []

print("\nRunning MsgGuard automated system tests...\n")

for test in test_cases:
    start = time.time()

    response = requests.post(
        BACKEND_URL,
        json={"text": test["text"], "claimedBrand": ""}
    )

    end = time.time()
    elapsed = end - start
    times.append(elapsed)

    if response.status_code != 200:
        print(f"[FAIL] {test['name']}")
        print("HTTP Error:", response.status_code)
        failed += 1
        continue

    result = response.json()
    actual_status = result.get("status")
    risk_score = result.get("riskScore")
    risk_level = result.get("riskLevel")
    reasons = result.get("reasons", [])

    is_pass = actual_status in test["expected"]

    if is_pass:
        passed += 1
        label = "PASS"
    else:
        failed += 1
        label = "FAIL"

    print(f"[{label}] {test['name']}")
    print("Expected:", test["expected"])
    print("Actual:", actual_status)
    print("Risk Level:", risk_level)
    print("Risk Score:", risk_score)
    print("Time:", round(elapsed, 2), "seconds")
    print("Top Reasons:", reasons[:3])
    print("-" * 60)

print("\nSummary")
print("Passed:", passed)
print("Failed:", failed)
print("Total:", len(test_cases))
print("Pass Rate:", round((passed / len(test_cases)) * 100, 2), "%")
print("Average Response Time:", round(sum(times) / len(times), 2), "seconds")