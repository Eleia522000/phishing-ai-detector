# -*- coding: utf-8 -*-

from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from datasets import load_dataset

from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report
)

from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer
)


# --------------------------------------------------
# 0. Project paths
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = PROJECT_ROOT / "models" / "bert_model"
CHECKPOINT_DIR = PROJECT_ROOT / "models" / "bert_model_checkpoints"
RESULTS_DIR = PROJECT_ROOT / "training_results"

RESULTS_DIR.mkdir(exist_ok=True)


# --------------------------------------------------
# 1. Load dataset
# --------------------------------------------------

ds = load_dataset("cybersectony/PhishingEmailDetectionv2.0")

print("Original dataset:")
print(ds)
print("\nOriginal columns:")
print(ds["train"].column_names)
print("\nFirst sample:")
print(ds["train"][0])


# --------------------------------------------------
# 2. Convert 4 labels into binary labels
# --------------------------------------------------
# Original:
# 0 = legitimate_email
# 1 = phishing_email
# 2 = legitimate_url
# 3 = phishing_url
#
# New:
# 0 = legitimate
# 1 = phishing

def convert_to_binary_label(example):
    original_label = int(example["label"])

    if original_label in [0, 2]:
        example["labels"] = 0
    elif original_label in [1, 3]:
        example["labels"] = 1
    else:
        example["labels"] = -1

    return example


ds = ds.map(convert_to_binary_label)


def keep_valid_labels(example):
    return example["labels"] in [0, 1]


ds = ds.filter(keep_valid_labels)


# --------------------------------------------------
# 3. Dataset info
# --------------------------------------------------

print("\nDataset after mapping:")
print(ds)

print("\nDataset Split:")
print("Train samples:", len(ds["train"]))
print("Validation samples:", len(ds["validation"]))
print("Test samples:", len(ds["test"]))

print("\nLabel distribution:")
for split_name in ds.keys():
    print(f"\n{split_name}:")
    print(ds[split_name].to_pandas()["labels"].value_counts())


# --------------------------------------------------
# 4. Model and tokenizer
# --------------------------------------------------

TEXT_COLUMN = "content"

model_name = "distilbert-base-uncased"

tokenizer = AutoTokenizer.from_pretrained(model_name)


# --------------------------------------------------
# 5. Tokenization
# --------------------------------------------------

def tokenize_function(example):
    return tokenizer(
        example[TEXT_COLUMN],
        padding="max_length",
        truncation=True,
        max_length=128
    )


tokenized_ds = ds.map(tokenize_function, batched=True)


# --------------------------------------------------
# 6. Keep only needed columns
# --------------------------------------------------

columns_to_keep = ["input_ids", "attention_mask", "labels"]

columns_to_remove = [
    col for col in tokenized_ds["train"].column_names
    if col not in columns_to_keep
]

tokenized_ds = tokenized_ds.remove_columns(columns_to_remove)
tokenized_ds.set_format("torch")


# --------------------------------------------------
# 7. Train / validation / test
# --------------------------------------------------

train_dataset = tokenized_ds["train"]
eval_dataset = tokenized_ds["validation"]
 


# --------------------------------------------------
# 8. Load BERT model
# --------------------------------------------------

model = AutoModelForSequenceClassification.from_pretrained(
    model_name,
    num_labels=2
)


# --------------------------------------------------
# 9. Metrics
# --------------------------------------------------

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=1)

    precision, recall, f1, _ = precision_recall_fscore_support(
        labels,
        predictions,
        average="binary",
        zero_division=0
    )

    accuracy = accuracy_score(labels, predictions)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }


# --------------------------------------------------
# 10. Training configuration
# --------------------------------------------------

training_args = TrainingArguments(
    output_dir=str(CHECKPOINT_DIR),
    eval_strategy="epoch",
    save_strategy="epoch",
    learning_rate=2e-5,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    num_train_epochs=2,
    weight_decay=0.01,
    logging_steps=50,
    load_best_model_at_end=True,
    save_total_limit=2,
    report_to="none"
)


# --------------------------------------------------
# 11. Trainer
# --------------------------------------------------

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=eval_dataset,
    compute_metrics=compute_metrics
)


# --------------------------------------------------
# 12. Train
# --------------------------------------------------

print("\nStarting BERT training...")
trainer.train()


# --------------------------------------------------
# 13. Save training logs
# --------------------------------------------------

logs_df = pd.DataFrame(trainer.state.log_history)
logs_path = RESULTS_DIR / "training_logs.csv"
logs_df.to_csv(logs_path, index=False)

print(f"\nTraining logs saved to: {logs_path}")


# --------------------------------------------------
# 14. Plot training loss
# --------------------------------------------------

loss_df = logs_df.dropna(subset=["loss"])

if not loss_df.empty:
    plt.figure()
    plt.plot(loss_df["epoch"], loss_df["loss"], marker="o")
    plt.xlabel("Epoch")
    plt.ylabel("Training Loss")
    plt.title("Training Loss Over Time")
    plt.grid(True)

    path = RESULTS_DIR / "training_loss.png"
    plt.savefig(path)
    plt.show()

    print(f"Training loss graph saved to: {path}")


# --------------------------------------------------
# 15. Plot evaluation loss
# --------------------------------------------------

eval_df = logs_df.dropna(subset=["eval_loss"])

if not eval_df.empty:
    plt.figure()
    plt.plot(eval_df["epoch"], eval_df["eval_loss"], marker="o")
    plt.xlabel("Epoch")
    plt.ylabel("Evaluation Loss")
    plt.title("Evaluation Loss Over Epochs")
    plt.grid(True)

    path = RESULTS_DIR / "evaluation_loss.png"
    plt.savefig(path)
    plt.show()

    print(f"Evaluation loss graph saved to: {path}")


# --------------------------------------------------
# 16. Evaluate
# --------------------------------------------------

print("\nEvaluating model...")
evaluation_results = trainer.evaluate()

print("\nEvaluation Results:")
print(evaluation_results)


# --------------------------------------------------
# 17. Final testing
# --------------------------------------------------

print("\nRunning final test predictions...")

predictions_output = trainer.predict(final_test_dataset)

logits = predictions_output.predictions
true_labels = predictions_output.label_ids
predicted_labels = np.argmax(logits, axis=1)

accuracy = accuracy_score(true_labels, predicted_labels)
cm = confusion_matrix(true_labels, predicted_labels)

report = classification_report(
    true_labels,
    predicted_labels,
    target_names=["Legitimate", "Phishing"],
    zero_division=0
)

print("\nFinal Accuracy:")
print(accuracy)

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(report)


# --------------------------------------------------
# 18. Save confusion matrix graph
# --------------------------------------------------

plt.figure()
plt.imshow(cm)
plt.title("Confusion Matrix")
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.xticks([0, 1], ["Legitimate", "Phishing"])
plt.yticks([0, 1], ["Legitimate", "Phishing"])

for i in range(cm.shape[0]):
    for j in range(cm.shape[1]):
        plt.text(j, i, cm[i, j], ha="center", va="center")

plt.colorbar()

cm_path = RESULTS_DIR / "confusion_matrix.png"
plt.savefig(cm_path)
plt.show()

print(f"Confusion matrix graph saved to: {cm_path}")


# --------------------------------------------------
# 19. Save metrics to text file
# --------------------------------------------------

metrics_path = RESULTS_DIR / "final_metrics.txt"

with open(metrics_path, "w", encoding="utf-8") as f:
    f.write("Final Accuracy:\n")
    f.write(str(accuracy))
    f.write("\n\nConfusion Matrix:\n")
    f.write(str(cm))
    f.write("\n\nClassification Report:\n")
    f.write(report)

print(f"Final metrics saved to: {metrics_path}")


# --------------------------------------------------
# 20. Save final model for backend
# --------------------------------------------------

print("\nSaving final BERT model...")

trainer.save_model(str(MODEL_DIR))
tokenizer.save_pretrained(str(MODEL_DIR))

print(f"\nBERT model saved successfully to: {MODEL_DIR}")