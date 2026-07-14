# -*- coding: utf-8 -*-
"""
Created on Sat Jun 27 02:17:56 2026

@author: enabf
This script performs incremental fine-tuning of the existing phishing-classification model. 
It loads the previous bert_model_v3 model and trains it on additional difficult examples stored in hard_cases_big.csv.
The input data is validated, cleaned, deduplicated, and tokenized before training. To preserve the knowledge learned by the previous model, 
the DistilBERT base layers are frozen and mainly the classification layers are updated. After training, the improved model and tokenizer are saved as
bert_model_v4 for use by the MsgGuard backend.
"""

from pathlib import Path
import pandas as pd

from datasets import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    DataCollatorWithPadding,
    TrainingArguments,
    Trainer,
)


PROJECT_DIR = Path(__file__).resolve().parent.parent

CURRENT_MODEL_PATH = PROJECT_DIR / "models" / "bert_model_v3"
NEW_DATA_PATH = PROJECT_DIR / "hard_cases_big.csv"
OUTPUT_MODEL_PATH = PROJECT_DIR / "models" / "bert_model_v4"


def load_hard_cases():
    if not NEW_DATA_PATH.exists():
        raise FileNotFoundError(f"Missing file: {NEW_DATA_PATH}")

    df = pd.read_csv(NEW_DATA_PATH)

    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must contain these columns: text,label")

    df = df[["text", "label"]].dropna()
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)

    bad_labels = set(df["label"].unique()) - {0, 1}
    if bad_labels:
        raise ValueError(f"Invalid labels found: {bad_labels}. Use only 0 or 1.")

    df = df.drop_duplicates(subset=["text", "label"])

    print("Loaded hard cases:", len(df))
    print(df["label"].value_counts())

    return df


def tokenize_dataset(dataset, tokenizer):
    def tokenize_batch(batch):
        return tokenizer(
            batch["text"],
            truncation=True,
            max_length=128,
        )

    return dataset.map(tokenize_batch, batched=True)


def freeze_distilbert_base(model):
    """
    Train mainly the classifier head.
    This reduces the chance of destroying what the old model already learned.
    """

    if hasattr(model, "distilbert"):
        for param in model.distilbert.parameters():
            param.requires_grad = False

    for name, param in model.named_parameters():
        if "classifier" in name.lower() or "pre_classifier" in name.lower():
            param.requires_grad = True

    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())

    print(f"Trainable parameters: {trainable:,} / {total:,}")


def main():
    if not CURRENT_MODEL_PATH.exists():
        raise FileNotFoundError(f"Model folder not found: {CURRENT_MODEL_PATH}")

    df = load_hard_cases()

    tokenizer = AutoTokenizer.from_pretrained(
        str(CURRENT_MODEL_PATH),
        local_files_only=True,
    )

    model = AutoModelForSequenceClassification.from_pretrained(
        str(CURRENT_MODEL_PATH),
        local_files_only=True,
        num_labels=2,
    )

    model.config.id2label = {
        0: "legitimate",
        1: "phishing",
    }

    model.config.label2id = {
        "legitimate": 0,
        "phishing": 1,
    }

    freeze_distilbert_base(model)

    dataset = Dataset.from_pandas(df.reset_index(drop=True))
    tokenized_dataset = tokenize_dataset(dataset, tokenizer)

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    training_args = TrainingArguments(
        output_dir=str(PROJECT_DIR / "training_output_incremental"),
        learning_rate=5e-5,
        per_device_train_batch_size=4,
        num_train_epochs=8,
        weight_decay=0.01,
        logging_steps=1,
        save_strategy="no",
        report_to="none",
    )

    trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_dataset,
    processing_class=tokenizer,
    data_collator=data_collator,
)

    trainer.train()

    OUTPUT_MODEL_PATH.mkdir(parents=True, exist_ok=True)

    trainer.save_model(str(OUTPUT_MODEL_PATH))
    tokenizer.save_pretrained(str(OUTPUT_MODEL_PATH))

    print(f"New model saved to: {OUTPUT_MODEL_PATH}")



if __name__ == "__main__":
    main()
