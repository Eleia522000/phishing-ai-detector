from pathlib import Path
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification


PROJECT_DIR = Path(__file__).resolve().parent.parent
BERT_MODEL_PATH = PROJECT_DIR / "models" / "bert_model_v3"

print("BERT path:", BERT_MODEL_PATH)
print("BERT exists:", BERT_MODEL_PATH.exists())

tokenizer = AutoTokenizer.from_pretrained(
    str(BERT_MODEL_PATH),
    local_files_only=True
)

model = AutoModelForSequenceClassification.from_pretrained(
    str(BERT_MODEL_PATH),
    local_files_only=True
)

model.eval()

print("\nModel config:")
print("num_labels:", model.config.num_labels)
print("id2label:", model.config.id2label)
print("label2id:", model.config.label2id)


test_messages = [
    {
        "expected": "phishing",
        "text": "Urgent: your account has been suspended. Verify your password now at http://secure-login-payments.example.com/verify"
    },
    {
        "expected": "phishing",
        "text": "Your payroll document is ready. Confirm your identity today or your access will be disabled: http://payroll-confirm.example.com/login"
    },
    {
        "expected": "phishing",
        "text": "Security alert. We detected unusual activity. Login immediately to restore your account."
    },
    {
        "expected": "legitimate",
        "text": "Hi team, tomorrow we will have a project meeting at 10:00. Please review the document before the call."
    },
    {
        "expected": "legitimate",
        "text": "Your package was delivered successfully. Thank you for shopping with us."
    },
    {
        "expected": "legitimate",
        "text": "Reminder: the server maintenance window is scheduled for Friday evening."
    },
]


for item in test_messages:
    text = item["text"]

    inputs = tokenizer(
        text,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=128
    )

    with torch.no_grad():
        outputs = model(**inputs)
        probabilities = torch.softmax(outputs.logits, dim=1)[0]

    class_0_probability = probabilities[0].item()
    class_1_probability = probabilities[1].item()
    predicted_class = torch.argmax(probabilities).item()

    print("\n----------------------------------------")
    print("Expected:", item["expected"])
    print("Text:", text)
    print("Class 0 probability:", round(class_0_probability * 100, 2), "%")
    print("Class 1 probability:", round(class_1_probability * 100, 2), "%")
    print("Predicted class:", predicted_class)