import pandas as pd

# 1. Load dataset
df = pd.read_csv("../data/processed/combined_dataset.csv")

print("Dataset loaded successfully")
print(df.head())

# 2. Check label distribution
print("\nLabel distribution:")
print(df["label"].value_counts())

# 3. Clean missing values
df = df.dropna()

# 4. Remove duplicate rows
df = df.drop_duplicates()

# 5. Convert labels to numbers
# phishing = 1, legitimate = 0
df["label_num"] = df["label"].map({
    "phishing": 1,
    "legitimate": 0
})

# 6. Combine message + URL into one text column
df["text"] = df["message_text"] + " " + df["url"]

# 7. Keep only useful columns
final_df = df[["text", "label_num"]]

# 8. Save cleaned dataset
final_df.to_csv("../data/processed/training_dataset.csv", index=False)

print("\nCleaned training dataset created successfully!")
print(final_df.head())

print("\nFinal label distribution:")
print(final_df["label_num"].value_counts())