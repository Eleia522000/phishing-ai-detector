"""MongoDB connection and analysis logging."""

from datetime import datetime

from pymongo import MongoClient

from Backend.config import (
    MONGO_COLLECTION_NAME,
    MONGO_DB_NAME,
    MONGO_URI,
)

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
except Exception as exc:
    print(f"MongoDB connection failed: {exc}")
    mongo_collection = None


def save_analysis_to_db(input_text: str, result: dict, response_time: float) -> None:
    """Save an analysis result when MongoDB logging is enabled."""
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
    except Exception as exc:
        print(f"Failed to save analysis to MongoDB: {exc}")
