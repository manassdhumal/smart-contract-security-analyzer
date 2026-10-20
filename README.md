# Smart Contract Vulnerability Detection and Classification System

A simple, readable, and explainable Python implementation based on our research paper:
> **"Machine Learning-Based Detection and Classification of Smart Contract Vulnerabilities: A Comparative Study"**

---

## Project Structure (Only 3 Main Python Files)

```text
smart-contract-security-analyzer/
├── train_model.py        # 1. Loads dataset, extracts TF-IDF, trains SVM & Logistic Regression, saves with joblib
├── predict.py            # 2. Loads saved models, predicts vulnerabilities, checks code patterns, returns dict
├── app.py                # 3. Single-page Streamlit web app for uploading/pasting Solidity contracts
├── requirements.txt      # Essential dependencies (pandas, numpy, scikit-learn, joblib, streamlit)
├── sample_contracts/     # 5 sample .sol contracts for live demonstration
├── models/saved/         # Saved .joblib models and TF-IDF vectorizers
└── data/raw/             # Pre-split dataset (balanced_stage1_resplit_721)
```

---

## Application Flow

```text
Upload or Paste Solidity Contract (.sol)
        ↓
TF-IDF Preprocessing (Comment Removal + Lowercase + Unigram/Bigram TF-IDF)
        ↓
Linear SVM Vulnerability Detection (Vulnerable vs. Clean)
        ↓
One-vs-Rest Logistic Regression Classification (8 Vulnerability Categories)
        ↓
Basic Solidity Code-Pattern Verification (Exact Line Numbers & Coding Mistake)
        ↓
Suggested Security Solution
```

---

## How to Run the Project

1. **Install dependencies:**
   ```powershell
   cd c:\Users\Sayali\Downloads\smart-contract-security-analyzer
   pip install -r requirements.txt
   ```

2. **(Optional) Retrain the models:**
   The trained models are already saved in `models/saved/`. To train them again:
   ```powershell
   python train_model.py
   ```

3. **Launch the Streamlit application:**
   ```powershell
   streamlit run app.py
   ```
