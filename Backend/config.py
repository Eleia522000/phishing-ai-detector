"""Shared configuration and constant data for the MsgGuard backend."""

import os
from pathlib import Path

from dotenv import load_dotenv

# Prevent an OpenMP duplicate-library crash on some Windows installations.
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=ENV_PATH, override=True)

print("ENV path:", ENV_PATH)
print("ENV exists:", ENV_PATH.exists())
# Project paths
PROJECT_DIR = Path(__file__).resolve().parent.parent
BERT_MODEL_PATH = PROJECT_DIR / "models" / "bert_model_v4"

# MongoDB settings
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "phishing_ai_detector_db")
MONGO_COLLECTION_NAME = os.getenv("MONGO_COLLECTION_NAME", "analysis_logs")

# Brand/domain data
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
    "login", "signin", "sign-in", "verify", "verification", "confirm",
    "identity", "update", "secure", "account", "password", "session",
    "auth", "staffportal", "portal", "benefits", "payroll", "salary",
    "document", "invoice", "payment", "billing", "support", "check",
    "unlock", "restore", "limited", "suspend", "suspended",
]

SUSPICIOUS_MESSAGE_WORDS = [
    "urgent", "immediately", "today", "expires", "expire", "within 24 hours",
    "before the end of the day", "account locked", "account suspended",
    "temporarily disabled", "access may be limited", "verify your account",
    "confirm your details", "confirm your information", "confirm your identity",
    "verify your identity", "update your information", "password", "credentials",
    "payroll", "salary", "benefits", "payment failed", "billing details",
    "security alert", "login now", "act now",
]

