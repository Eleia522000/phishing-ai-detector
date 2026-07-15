"""Flask entry point for the MsgGuard backend."""

import sys
import time
from pathlib import Path

# Ensure imports work with both:
#   python Backend/msgguard.py
# and:
#   cd Backend && python msgguard.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, jsonify, request
from flask_cors import CORS

from Backend.database import mongo_collection, save_analysis_to_db
from Backend.decision.decision_engine import (
    analyze_input,
    is_safe_trusted_url_context,
)
from Backend.services.bert_service import BERT_AVAILABLE, bert_text_model_score

# Compatibility imports: existing tests that import functions directly from
# msgguard.py can continue working after the code is split into modules.
from Backend.analyzers.brand_analyzer import (
    brand_domain_consistency_check,
    detect_brand_from_url,
    detect_claimed_brand,
)
from Backend.analyzers.domain_analyzer import (
    compute_domain_age_days,
    domain_age_verification,
    extract_rdap_registrar,
    hosting_origin_consistency_analysis,
    lookup_hosting_origin,
    parse_domain_date,
    resolve_ip,
    safe_get_creation_date,
    safe_get_whois_info,
)
from Backend.analyzers.message_analyzer import (
    analyze_message_wording,
    contains_high_risk_phishing_language,
    contains_strong_legitimate_context,
)
from Backend.analyzers.url_analyzer import (
    analyze_url_structure,
    extract_domain_parts,
    extract_subdomain,
    extract_text_without_urls,
    extract_urls,
    is_trusted_official_domain,
    is_url_only_input,
    normalize_domain,
)
from Backend.utils.helpers import (
    calculate_similarity,
    dedupe_keep_order,
    edit_distance,
    normalize_homoglyphs,
    split_domain_tokens,
)

app = Flask(__name__)
CORS(app)

print("RUNNING MSGGUARD BACKEND - MODULAR VERSION")


@app.route("/", methods=["GET"])
def home():
    """Return a simple backend status message."""
    return (
        "MsgGuard backend works with BERT, message analysis, homoglyph "
        "detection, URL structure checks, and URL identity checks"
    )


@app.route("/health", methods=["GET"])
def health():
    """Return backend, BERT, and MongoDB availability information."""
    return jsonify({
        "success": True,
        "message": "MsgGuard backend is running",
        "bertAvailable": BERT_AVAILABLE,
        "mongoLoggingEnabled": mongo_collection is not None,
    })


def _run_analysis(text: str, claimed_brand=None):
    """Run analysis, attach response time, and save the result."""
    start_time = time.time()
    result = analyze_input(text, claimed_brand)
    response_time = time.time() - start_time

    result["success"] = True
    result["responseTime"] = response_time
    save_analysis_to_db(text, result, response_time)
    return result


@app.route("/analyze", methods=["GET", "POST", "OPTIONS"])
def analyze():
    """Analyze submitted text or a URL and return a structured JSON result."""
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    if request.method == "GET":
        text = str(request.args.get("text", "")).strip()
        claimed_brand = (
            request.args.get("claimedBrand") or ""
        ).strip() or None

        if not text:
            return jsonify({
                "success": False,
                "error": "Input text cannot be empty",
                "message": "Please enter a message before analyzing.",
            }), 400

        return jsonify(_run_analysis(text, claimed_brand))

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "error": "Missing JSON body",
            "message": "Please enter a message before analyzing.",
        }), 400

    text = str(data.get("text") or data.get("message") or "").strip()
    claimed_brand = (data.get("claimedBrand") or "").strip() or None

    if not text:
        return jsonify({
            "success": False,
            "error": "Input text cannot be empty",
            "message": "Please enter a message before analyzing.",
        }), 400

    return jsonify(_run_analysis(text, claimed_brand))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
