import requests
import time
from tabulate import tabulate

API_URL = "http://127.0.0.1:5000/analyze"

tests = [
    {
        "name": "Legitimate Microsoft",
        "text": "Hi Enab, our meeting is tomorrow at 10:00. https://teams.microsoft.com",
        "expected": "Legitimate"
    },
    {
        "name": "Legitimate Google",
        "text": "Visit https://google.com for more information.",
        "expected": "Legitimate"
    },
    {
        "name": "Classic PayPal Phishing",
        "text": "Your PayPal account has been suspended. Verify immediately: http://paypa1-login.xyz",
        "expected": "Phishing"
    },
    {
        "name": "Bank Phishing",
        "text": "Your bank account is locked. Update now: http://secure-bank-login.xyz",
        "expected": "Phishing"
    },
    {
        "name": "Message Without URL",
        "text": "Congratulations! You have won a free iPhone. Reply now.",
        "expected": "Phishing"
    },
    {
        "name": "Trusted Amazon",
        "text": "Track your package here: https://amazon.com/orders",
        "expected": "Legitimate"
    },
    {
        "name": "URL Only",
        "text": "https://google.com",
        "expected": "Legitimate"
    },
    {
        "name": "Homoglyph URL",
        "text": "http://paypa1-login.xyz",
        "expected": "Phishing"
    },
    {
        "name": "Multiple URLs",
        "text": "https://google.com http://paypa1-login.xyz",
        "expected": "Phishing"
    },
    {
        "name": "Long Message",
        "text": "Hello " * 1000,
        "expected": "Legitimate"
    },
    {
        "name": "Hebrew Message",
        "text": "לחץ כאן כדי לעדכן את החשבון שלך",
        "expected": None
    },
    {
        "name": "Arabic Message",
        "text": "اضغط هنا لتحديث حسابك",
        "expected": None
    },
]

results = []

passed = 0
total_time = 0

print("=" * 70)
print("MSGGUARD END-TO-END SYSTEM VALIDATION")
print("=" * 70)

for test in tests:

    start = time.time()

    try:
        response = requests.post(
            API_URL,
            json={
                "text": test["text"],
                "claimedBrand": None
            },
            timeout=30
        )

        elapsed = time.time() - start
        total_time += elapsed

        if response.status_code == 200:

            data = response.json()

            prediction = data.get("status", "Unknown")

            if test["expected"] is None:
                success = True
            else:
                success = prediction.lower() == test["expected"].lower()

            if success:
                passed += 1

            results.append([
                test["name"],
                prediction,
                test["expected"] if test["expected"] else "-",
                "PASS" if success else "FAIL",
                f"{elapsed:.2f}s"
            ])

        else:

            results.append([
                test["name"],
                "ERROR",
                test["expected"],
                "FAIL",
                "-"
            ])

    except Exception as e:

        results.append([
            test["name"],
            str(e),
            test["expected"],
            "FAIL",
            "-"
        ])

print(tabulate(
    results,
    headers=["Test", "Prediction", "Expected", "Status", "Time"],
    tablefmt="grid"
))

print("\n")

print("=" * 70)
print("SUMMARY")
print("=" * 70)

print(f"Tests Executed : {len(tests)}")
print(f"Passed         : {passed}")
print(f"Failed         : {len(tests)-passed}")
print(f"Success Rate   : {(passed/len(tests))*100:.1f}%")
print(f"Average Time   : {total_time/len(tests):.2f} sec")
