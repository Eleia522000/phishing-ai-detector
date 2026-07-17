"""BERT model loading and inference service."""

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from Backend.config import BERT_MODEL_PATH
from Backend.utils.helpers import dedupe_keep_order

bert_tokenizer = None
bert_model = None
BERT_AVAILABLE = False

print("BERT path:", BERT_MODEL_PATH)
print("BERT exists:", BERT_MODEL_PATH.exists())

try:
    # Load the locally saved model only when the configured model folder exists.
    if BERT_MODEL_PATH.exists():
        bert_tokenizer = AutoTokenizer.from_pretrained(
            str(BERT_MODEL_PATH),
            local_files_only=True,
        )
        bert_model = AutoModelForSequenceClassification.from_pretrained(
            str(BERT_MODEL_PATH),
            local_files_only=True,
        )
        bert_model.eval()
        BERT_AVAILABLE = True
        print("BERT model loaded successfully")
    else:
        print("BERT model folder not found. Backend will run without BERT.")
except Exception as exc:
    print(f"BERT model loading failed: {exc}")
    print("Backend will continue running without BERT.")


def bert_text_model_score(text: str):
    """Return BERT risk score, findings, and phishing probability."""
    if not BERT_AVAILABLE or bert_tokenizer is None or bert_model is None:
        return 0, [
            "BERT model is not available. Train the model first and save it "
            "under models/bert_model."
        ], None

    try:
        # Tokenize and limit the input length to match the model configuration.
        inputs = bert_tokenizer(
            text,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=128,
        )

        # Disable gradient calculation because this function performs inference only.
        with torch.no_grad():
            outputs = bert_model(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=1)

        phishing_probability = probabilities[0][1].item()
        score = int(phishing_probability * 50)

        findings = [f"BERT phishing probability: {phishing_probability:.2%}"]

        if phishing_probability >= 0.80:
            findings.append("High-risk phishing pattern detected by BERT model")
        elif phishing_probability >= 0.50:
            findings.append("Moderate phishing pattern detected by BERT model")
        else:
            findings.append("Low phishing probability according to BERT model")

        return score, dedupe_keep_order(findings), phishing_probability
    except Exception as exc:
        return 0, [f"BERT model could not analyze input: {str(exc)}"], None