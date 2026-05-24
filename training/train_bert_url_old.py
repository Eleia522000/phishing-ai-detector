import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
from datasets import Dataset

# Load dataset
df = pd.read_csv("../data/processed/final_real_dataset.csv")

# Make sure columns are correct
df = df[["url", "label"]].dropna()
df["url"] = df["url"].astype(str)
df["label"] = df["label"].astype(int)

# Split dataset
train_df, test_df = train_test_split(
    df,
    test_size=0.2,
    random_state=42,
    stratify=df["label"]
)

# Convert pandas to HuggingFace dataset
train_dataset = Dataset.from_pandas(train_df)
test_dataset = Dataset.from_pandas(test_df)

# Use a small BERT model first because it is faster
model_name = "distilbert-base-uncased"

tokenizer = AutoTokenizer.from_pretrained(model_name)

def tokenize_function(example):
    return tokenizer(
        example["url"],
        padding="max_length",
        truncation=True,
        max_length=128
    )

train_dataset = train_dataset.map(tokenize_function, batched=True)
test_dataset = test_dataset.map(tokenize_function, batched=True)

train_dataset = train_dataset.remove_columns(["url", "__index_level_0__"])
test_dataset = test_dataset.remove_columns(["url", "__index_level_0__"])

train_dataset.set_format("torch")
test_dataset.set_format("torch")

model = AutoModelForSequenceClassification.from_pretrained(
    model_name,
    num_labels=2
)

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions = logits.argmax(axis=-1)

    acc = accuracy_score(labels, predictions)
    report = classification_report(labels, predictions, output_dict=True)

    return {
        "accuracy": acc,
        "phishing_precision": report["1"]["precision"],
        "phishing_recall": report["1"]["recall"],
        "phishing_f1": report["1"]["f1-score"],
    }

training_args = TrainingArguments(
    output_dir="../models/bert_phishing",
    eval_strategy="epoch",
    save_strategy="epoch",
    learning_rate=2e-5,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    num_train_epochs=2,
    weight_decay=0.01,
    logging_dir="../models/bert_logs",
    logging_steps=50,
    load_best_model_at_end=True,
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset,
    compute_metrics=compute_metrics,
)

print("Starting BERT training...")
trainer.train()

print("Evaluating BERT model...")
results = trainer.evaluate()
print(results)

print("Saving BERT model...")
trainer.save_model("../models/bert_phishing_final")
tokenizer.save_pretrained("../models/bert_phishing_final")

print("BERT training completed and model saved!")