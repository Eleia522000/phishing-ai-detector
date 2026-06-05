# -*- coding: utf-8 -*-

"""
External Evaluation Script for MsgGuard

Purpose:
- Test MsgGuard on external datasets that were NOT used for training.
- Sends every sample to the running Flask backend /analyze endpoint.
- Calculates:
  Accuracy, Precision, Recall, F1-score, Confusion Matrix, Average response time.

Before running this script:
1. Run the backend first:
   python msgguard.py

2. Then run this script, for example:
   python external_evaluation.py --message_csv phishing_email.csv --per_class 500

Output files will be saved to:
   external_evaluation_results/
"""

import argparse
import time
from pathlib import Path

import requests
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)


# --------------------------------------------------
# Configuration
# --------------------------------------------------

BACKEND_URL = "http://127.0.0.1:5000/analyze"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "external_evaluation_results"
RESULTS_DIR.mkdir(exist_ok=True)

OUTPUT_CSV = RESULTS_DIR / "external_evaluation_results.csv"
OUTPUT_REPORT = RESULTS_DIR / "external_evaluation_report.txt"
OUTPUT_CM = RESULTS_DIR / "external_confusion_matrix.png"


# --------------------------------------------------
# Label and column handling
# --------------------------------------------------

def normalize_label(value):
    """
    Convert labels from different datasets into:
    0 = Legitimate
    1 = Phishing

    Supports common formats:
    - 0 / 1
    - legitimate / phishing
    - safe / malicious
    - ham / spam
    - benign / phishing
    """
    if value is None:
        return None

    text = str(value).strip().lower()

    legitimate_values = {
        "0",
        "legitimate",
        "legit",
        "safe",
        "benign",
        "ham",
        "not phishing",
        "non-phishing",
        "false",
        "normal",
    }

    phishing_values = {
        "1",
        "phishing",
        "phish",
        "malicious",
        "spam",
        "smishing",
        "suspicious",
        "true",
        "fraud",
    }

    if text in legitimate_values:
        return 0

    if text in phishing_values:
        return 1

    return None


def detect_text_column(df):
    """
    Automatically detect the column containing the email/message/url text.
    Your current dataset uses: text_combined
    """
    possible_columns = [
        "text_combined",
        "text",
        "message",
        "email",
        "body",
        "content",
        "subject",
        "Email Text",
        "Email",
        "Message",
        "url",
        "URL",
        "URL_Column",
    ]

    for col in possible_columns:
        if col in df.columns:
            return col

    # Fallback: use first string/object column
    for col in df.columns:
        if df[col].dtype == "object":
            return col

    raise ValueError(f"Could not detect text/url column. Columns found: {list(df.columns)}")


def detect_label_column(df):
    """
    Automatically detect the column containing the label.
    Your current dataset uses: label
    """
    possible_columns = [
        "label",
        "Label",
        "class",
        "Class",
        "status",
        "Status",
        "type",
        "Type",
        "Category",
        "category",
        "phishing",
        "is_phishing",
        "result",
        "Result",
    ]

    for col in possible_columns:
        if col in df.columns:
            return col

    raise ValueError(f"Could not detect label column. Columns found: {list(df.columns)}")


def balance_sample(df, text_col, label_col, per_class_limit):
    """
    Creates a balanced test set:
    - N legitimate samples
    - N phishing samples
    """
    df = df[[text_col, label_col]].dropna().copy()

    df["binary_label"] = df[label_col].apply(normalize_label)
    df = df[df["binary_label"].isin([0, 1])]

    if df.empty:
        raise ValueError(
            "After label normalization, no valid rows remained. "
            "Check label values in the dataset."
        )

    legit_df = df[df["binary_label"] == 0].head(per_class_limit)
    phish_df = df[df["binary_label"] == 1].head(per_class_limit)

    if legit_df.empty:
        print("WARNING: No legitimate samples detected.")

    if phish_df.empty:
        print("WARNING: No phishing samples detected.")

    balanced = pd.concat([legit_df, phish_df], ignore_index=True)
    balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)

    return balanced


# --------------------------------------------------
# Backend prediction
# --------------------------------------------------

def backend_predict(text):
    """
    Sends one sample to the backend and converts the system result to binary:
    0 = Legitimate
    1 = Phishing/Suspicious
    """
    start = time.time()

    response = requests.post(
        BACKEND_URL,
        json={
            "text": str(text),
            "claimedBrand": "",
        },
        timeout=30,
    )

    elapsed = time.time() - start

    if response.status_code != 200:
        raise RuntimeError(f"Backend error {response.status_code}: {response.text}")

    result = response.json()
    status = str(result.get("status", "")).lower()

    # In security evaluation, "Suspicious" is treated as risky/phishing.
    if status in ["phishing", "suspicious"]:
        predicted_label = 1
    else:
        predicted_label = 0

    return {
        "predicted_label": predicted_label,
        "status": result.get("status"),
        "riskLevel": result.get("riskLevel"),
        "riskScore": result.get("riskScore"),
        "reasons": result.get("reasons", []),
        "response_time": elapsed,
    }


# --------------------------------------------------
# Evaluation
# --------------------------------------------------

def evaluate_dataframe(df, text_col, label_col, dataset_name, sample_type, per_class_limit):
    balanced = balance_sample(df, text_col, label_col, per_class_limit)

    print("\n" + "=" * 70)
    print(f"Evaluating dataset: {dataset_name}")
    print(f"Sample type: {sample_type}")
    print("Text column:", text_col)
    print("Label column:", label_col)
    print("Total samples:", len(balanced))
    print("Legitimate:", len(balanced[balanced["binary_label"] == 0]))
    print("Phishing:", len(balanced[balanced["binary_label"] == 1]))
    print("=" * 70 + "\n")

    rows = []

    for index, row in balanced.iterrows():
        input_text = row[text_col]
        true_label = int(row["binary_label"])

        try:
            prediction = backend_predict(input_text)

            rows.append({
                "dataset": dataset_name,
                "sample_type": sample_type,
                "input": input_text,
                "true_label": true_label,
                "predicted_label": prediction["predicted_label"],
                "status": prediction["status"],
                "riskLevel": prediction["riskLevel"],
                "riskScore": prediction["riskScore"],
                "response_time": prediction["response_time"],
                "top_reasons": " | ".join(prediction["reasons"][:5]),
                "error": "",
            })

            print(
                f"[{index + 1}/{len(balanced)}] "
                f"true={true_label} "
                f"pred={prediction['predicted_label']} "
                f"status={prediction['status']} "
                f"score={prediction['riskScore']} "
                f"time={prediction['response_time']:.2f}s"
            )

        except Exception as e:
            rows.append({
                "dataset": dataset_name,
                "sample_type": sample_type,
                "input": input_text,
                "true_label": true_label,
                "predicted_label": None,
                "status": None,
                "riskLevel": None,
                "riskScore": None,
                "response_time": None,
                "top_reasons": "",
                "error": str(e),
            })

            print(f"[ERROR] sample {index + 1}: {e}")

    return pd.DataFrame(rows)


def save_metrics(results_df):
    clean_df = results_df.dropna(subset=["predicted_label"]).copy()

    if clean_df.empty:
        raise ValueError("No valid predictions were produced. Check backend connection or dataset format.")

    y_true = clean_df["true_label"].astype(int)
    y_pred = clean_df["predicted_label"].astype(int)

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    average_time = clean_df["response_time"].mean()

    report = classification_report(
        y_true,
        y_pred,
        target_names=["Legitimate", "Phishing"],
        zero_division=0,
    )

    print("\n" + "=" * 70)
    print("Final External Evaluation Results")
    print("=" * 70)
    print("Total valid samples:", len(clean_df))
    print("Accuracy:", round(accuracy, 4))
    print("Precision:", round(precision, 4))
    print("Recall:", round(recall, 4))
    print("F1-score:", round(f1, 4))
    print("Average response time:", round(average_time, 2), "seconds")
    print("\nConfusion Matrix:")
    print(cm)
    print("\nClassification Report:")
    print(report)

    results_df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")

    with open(OUTPUT_REPORT, "w", encoding="utf-8") as f:
        f.write("MsgGuard External Evaluation Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Total valid samples: {len(clean_df)}\n")
        f.write(f"Accuracy: {accuracy:.4f}\n")
        f.write(f"Precision: {precision:.4f}\n")
        f.write(f"Recall: {recall:.4f}\n")
        f.write(f"F1-score: {f1:.4f}\n")
        f.write(f"Average response time: {average_time:.2f} seconds\n\n")
        f.write("Confusion Matrix:\n")
        f.write(str(cm))
        f.write("\n\nClassification Report:\n")
        f.write(report)

    plt.figure(figsize=(6, 5))
    plt.imshow(cm)
    plt.title("External Evaluation Confusion Matrix")
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.xticks([0, 1], ["Legitimate", "Phishing"])
    plt.yticks([0, 1], ["Legitimate", "Phishing"])

    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, cm[i, j], ha="center", va="center")

    plt.colorbar()
    plt.tight_layout()
    plt.savefig(OUTPUT_CM)
    plt.close()

    print("\nSaved files:")
    print(OUTPUT_CSV)
    print(OUTPUT_REPORT)
    print(OUTPUT_CM)


# --------------------------------------------------
# Dataset loading
# --------------------------------------------------

def load_csv_dataset(path):
    df = pd.read_csv(path)

    print("\nCSV loaded successfully:", path)
    print("Columns found:", list(df.columns))

    text_col = detect_text_column(df)
    label_col = detect_label_column(df)

    print("Detected text/url column:", text_col)
    print("Detected label column:", label_col)

    print("\nLabel distribution before normalization:")
    print(df[label_col].value_counts(dropna=False).head(20))

    return df, text_col, label_col


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--message_csv",
        type=str,
        default=None,
        help="CSV file containing external message/email dataset.",
    )

    parser.add_argument(
        "--url_csv",
        type=str,
        default=None,
        help="CSV file containing external URL dataset.",
    )

    parser.add_argument(
        "--per_class",
        type=int,
        default=500,
        help="Number of legitimate and phishing samples per dataset.",
    )

    args = parser.parse_args()

    all_results = []

    if args.message_csv:
        df, text_col, label_col = load_csv_dataset(args.message_csv)
        message_results = evaluate_dataframe(
            df=df,
            text_col=text_col,
            label_col=label_col,
            dataset_name=Path(args.message_csv).name,
            sample_type="messages",
            per_class_limit=args.per_class,
        )
        all_results.append(message_results)

    if args.url_csv:
        df, text_col, label_col = load_csv_dataset(args.url_csv)
        url_results = evaluate_dataframe(
            df=df,
            text_col=text_col,
            label_col=label_col,
            dataset_name=Path(args.url_csv).name,
            sample_type="urls",
            per_class_limit=args.per_class,
        )
        all_results.append(url_results)

    if not all_results:
        print("\nNo dataset selected.")
        print("\nExamples:")
        print("python external_evaluation.py --message_csv phishing_email.csv --per_class 500")
        print("python external_evaluation.py --url_csv PhiUSIIL_Phishing_URL_Dataset.csv --per_class 500")
        print("python external_evaluation.py --message_csv phishing_email.csv --url_csv PhiUSIIL_Phishing_URL_Dataset.csv --per_class 500")
        return

    results_df = pd.concat(all_results, ignore_index=True)
    save_metrics(results_df)


if __name__ == "__main__":
    main()

