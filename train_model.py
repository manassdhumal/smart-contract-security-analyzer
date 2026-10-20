"""
train_model.py
--------------
Simple and readable training script for Smart Contract Vulnerability Detection.

What this file does:
1. Loads the pre-split Solidity dataset from `data/raw/balanced_stage1_resplit_721/`.
2. Cleans Solidity code (removes comments, normalizes spaces, converts to lowercase).
3. Extracts TF-IDF lexical features (unigrams and bigrams, up to 50,000 features).
4. Trains a Linear SVM model for binary detection (Clean = 0, Vulnerable = 1).
5. Trains a One-vs-Rest Logistic Regression model to classify 8 vulnerability categories.
6. Evaluates both models on the held-out test split and saves them using joblib.
"""

import json
import re
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.multiclass import OneVsRestClassifier
from sklearn.svm import LinearSVC

# ---------------------------------------------------------------------------
# 1. File Paths and Vulnerability Categories
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data" / "raw" / "balanced_stage1_resplit_721"
BINARY_SPLIT_DIR = DATA_DIR / "has_vul_721_stratified_v1"
MULTILABEL_SPLIT_DIR = DATA_DIR / "vul_type_721_stratified_v1"

MODELS_DIR = BASE_DIR / "models" / "saved"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# The 8 vulnerability categories from the research paper
VULNERABILITY_CATEGORIES = [
    "access_control",
    "arithmetic",
    "bad_randomness",
    "denial_service",
    "front_running",
    "reentrancy",
    "time_manipulation",
    "unchecked_low_calls",
]


# ---------------------------------------------------------------------------
# 2. Basic Solidity Preprocessing Function
# ---------------------------------------------------------------------------
def preprocess_solidity_code(source_code):
    """
    Perform the 5 preprocessing steps from the research paper:
    1. Convert list of lines to a single string (if needed).
    2. Remove single-line comments (// ...).
    3. Remove multi-line block comments (/* ... */).
    4. Normalize multiple spaces/newlines into a single space.
    5. Convert all text to lowercase and strip extra whitespace.
    """
    if isinstance(source_code, list):
        code_text = "\n".join(str(line) for line in source_code)
    else:
        code_text = str(source_code)

    # Remove block comments /* ... */
    code_text = re.sub(r"/\*.*?\*/", " ", code_text, flags=re.DOTALL)
    # Remove single-line comments // ...
    code_text = re.sub(r"//.*?$", " ", code_text, flags=re.MULTILINE)
    # Replace multiple spaces, tabs, or newlines with a single space
    code_text = re.sub(r"\s+", " ", code_text)

    return code_text.lower().strip()


# ---------------------------------------------------------------------------
# 3. Dataset Loading Helper Functions
# ---------------------------------------------------------------------------
def load_binary_dataset(json_path):
    """Load Solidity code and binary label (0 = Clean, 1 = Vulnerable) from a JSON split."""
    with open(json_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    df = pd.DataFrame(records)
    texts = [preprocess_solidity_code(ctx) for ctx in df["context"]]
    labels = df["has_vulnerability"].astype(int).to_numpy()
    return texts, labels


def load_multilabel_dataset(json_path):
    """Load Solidity code and 8-category multi-hot labels from a JSON split."""
    with open(json_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    texts = []
    label_matrix = np.zeros((len(records), len(VULNERABILITY_CATEGORIES)), dtype=int)

    for i, row in enumerate(records):
        texts.append(preprocess_solidity_code(row.get("context", [])))

        # Get vulnerability category list for this contract
        row_labels = row.get("label", [])
        if isinstance(row_labels, str):
            row_labels = [row_labels]

        for cat_idx, cat_name in enumerate(VULNERABILITY_CATEGORIES):
            if cat_name in row_labels:
                label_matrix[i, cat_idx] = 1

    return texts, label_matrix


# ---------------------------------------------------------------------------
# 4. Model 1: Train Linear SVM for Binary Vulnerability Detection
# ---------------------------------------------------------------------------
def train_binary_svm():
    """Train Linear SVM on TF-IDF features to detect if a contract is vulnerable."""
    print("Step 1/2: Loading binary detection dataset splits...")
    X_train_raw, y_train = load_binary_dataset(BINARY_SPLIT_DIR / "train.json")
    X_test_raw, y_test = load_binary_dataset(BINARY_SPLIT_DIR / "test.json")
    print(f"  Training samples: {len(X_train_raw)} | Testing samples: {len(X_test_raw)}")

    # Configure TF-IDF exactly as specified in the research paper
    print("  Extracting TF-IDF features (max_features=50000, unigrams + bigrams)...")
    binary_tfidf = TfidfVectorizer(
        analyzer="word",
        token_pattern=r"(?u)\b\w+\b",
        ngram_range=(1, 2),
        max_features=50000,
        min_df=2,
        sublinear_tf=True,
    )
    X_train_tfidf = binary_tfidf.fit_transform(X_train_raw)
    X_test_tfidf = binary_tfidf.transform(X_test_raw)

    # Train Linear SVM (primary model from the research paper)
    print("  Training Linear SVM classifier...")
    svm_model = LinearSVC(C=1.0, class_weight="balanced", random_state=42)
    svm_model.fit(X_train_tfidf, y_train)

    # Evaluate on held-out test set
    y_pred = svm_model.predict(X_test_tfidf)
    acc = accuracy_score(y_test, y_pred) * 100
    prec = precision_score(y_test, y_pred, zero_division=0) * 100
    rec = recall_score(y_test, y_pred, zero_division=0) * 100
    f1 = f1_score(y_test, y_pred, zero_division=0) * 100
    print(f"  Linear SVM Test Results -> Accuracy: {acc:.2f}%, Precision: {prec:.2f}%, Recall: {rec:.2f}%, F1: {f1:.2f}%")

    # Save vectorizer and trained SVM model using joblib
    joblib.dump(binary_tfidf, MODELS_DIR / "binary_tfidf.joblib")
    joblib.dump(svm_model, MODELS_DIR / "linear_svm.joblib")
    print(f"  Saved binary_tfidf.joblib and linear_svm.joblib to {MODELS_DIR}\n")


# ---------------------------------------------------------------------------
# 5. Model 2: Train One-vs-Rest Logistic Regression for Vulnerability Types
# ---------------------------------------------------------------------------
def train_multilabel_logistic_regression():
    """Train One-vs-Rest Logistic Regression to classify the 8 vulnerability categories."""
    print("Step 2/2: Loading multi-label vulnerability type dataset splits...")
    X_train_raw, y_train = load_multilabel_dataset(MULTILABEL_SPLIT_DIR / "train.json")
    X_test_raw, y_test = load_multilabel_dataset(MULTILABEL_SPLIT_DIR / "test.json")
    print(f"  Training samples: {len(X_train_raw)} | Testing samples: {len(X_test_raw)}")

    # Fit TF-IDF on multi-label training data
    print("  Extracting TF-IDF features for multi-label classification...")
    multilabel_tfidf = TfidfVectorizer(
        analyzer="word",
        token_pattern=r"(?u)\b\w+\b",
        ngram_range=(1, 2),
        max_features=50000,
        min_df=2,
        sublinear_tf=True,
    )
    X_train_tfidf = multilabel_tfidf.fit_transform(X_train_raw)
    X_test_tfidf = multilabel_tfidf.transform(X_test_raw)

    # Train One-vs-Rest Logistic Regression
    print("  Training One-vs-Rest Logistic Regression classifier...")
    base_lr = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
    ovr_model = OneVsRestClassifier(base_lr, n_jobs=-1)
    ovr_model.fit(X_train_tfidf, y_train)

    # Evaluate on held-out test set
    y_pred = ovr_model.predict(X_test_tfidf)
    micro_f1 = f1_score(y_test, y_pred, average="micro", zero_division=0) * 100
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0) * 100
    print(f"  Multi-Label Test Results -> Micro-F1: {micro_f1:.2f}%, Macro-F1: {macro_f1:.2f}%")

    # Save vectorizer and trained multi-label model using joblib
    joblib.dump(multilabel_tfidf, MODELS_DIR / "multilabel_tfidf.joblib")
    joblib.dump(
        {
            "classifier": ovr_model,
            "categories": VULNERABILITY_CATEGORIES,
        },
        MODELS_DIR / "multilabel_ovr_lr.joblib",
    )
    print(f"  Saved multilabel_tfidf.joblib and multilabel_ovr_lr.joblib to {MODELS_DIR}")


if __name__ == "__main__":
    print("=== Starting Smart Contract Vulnerability Model Training ===\n")
    train_binary_svm()
    train_multilabel_logistic_regression()
    print("\n=== Training Complete! All models saved successfully. ===")
