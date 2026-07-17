"""Main Flask application for the MsgGuard backend API."""

import sys
import time
from pathlib import Path

# Add the project root to Python's module search path so the application can
# be started either from the project root or directly from the Backend folder.
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

# Re-export selected analysis functions to preserve compatibility with tests
# and other code that previously imported them directly from msgguard.py.
# These imports are intentionally exposed from this module and may therefore
# appear unused within this file.
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

# Create the Flask application and allow requests from the frontend.
app = Flask(__name__)
CORS(app)

print("RUNNING MSGGUARD BACKEND - MODULAR VERSION")


@app.route("/", methods=["GET"])
def home():
    """Return a simple status message describing the backend capabilities."""
    return (
        "MsgGuard backend works with BERT, message analysis, homoglyph "
        "detection, URL structure checks, and URL identity checks"
    )


@app.route("/health", methods=["GET"])
def health():
    """Return the availability status of the backend and its main services."""
    return jsonify({
        "success": True,
        "message": "MsgGuard backend is running",
        "bertAvailable": BERT_AVAILABLE,
        "mongoLoggingEnabled": mongo_collection is not None,
    })


def _run_analysis(text: str, claimed_brand=None):
    """Analyze the input, record execution time, and store the result."""
    start_time = time.time()

    # Run the complete phishing-detection pipeline.
    result = analyze_input(text, claimed_brand)

    # Measure the total processing time for the API response.
    response_time = time.time() - start_time

    # Add general API metadata to the analysis result.
    result["success"] = True
    result["responseTime"] = response_time

    # Store the analysis when MongoDB logging is available.
    save_analysis_to_db(text, result, response_time)

    return result


@app.route("/analyze", methods=["GET", "POST", "OPTIONS"])
def analyze():
    """Handle analysis requests submitted through GET or POST."""
    # Respond to browser preflight requests used by cross-origin clients.
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    # Support analysis requests that provide input through query parameters.
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

    # Read the JSON body for POST requests without raising an exception when
    # the request body is missing or contains invalid JSON.
    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "error": "Missing JSON body",
            "message": "Please enter a message before analyzing.",
        }), 400

    # Accept either "text" or "message" to maintain compatibility with
    # different frontend request formats.
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
    # Listen on all local network interfaces so the frontend can connect from
    # the same computer or from another device on the local network.
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=False,
    )