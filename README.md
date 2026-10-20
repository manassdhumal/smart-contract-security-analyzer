# AegisGuard - Smart Contract Security Analyzer

A modern, explainable AI and AST-based vulnerability detection system for Ethereum Solidity smart contracts, implementing the methodology from:
> **"Machine Learning-Based Detection and Classification of Smart Contract Vulnerabilities: A Comparative Study"**

---

## Key Features

- **Embedded Monaco IDE & Solidity Highlighting**: Full Monaco code studio equipped with custom Solidity keywords, tokens, shortcuts (<kbd>Ctrl</kbd> + <kbd>Enter</kbd> to audit), and resilient line-gutter fallback.
- **Web3 Blockchain Contract Importer**: Directly fetch verified Solidity source code by contract address from Ethereum Mainnet, Sepolia, Base, Arbitrum, Optimism, Polygon, and Gnosis via decentralized Blockscout and Etherscan API V2.
- **Interactive Remediation & Git-Style Diffs**: Visual split comparison (Vulnerable vs Remediated) with automated patch generator and 1-click **"Apply Patch Into Editor"** replacement.
- **Dual-Stage ML Detection**: 
  - **Stage 1 (Binary Detection)**: Linear Support Vector Machine (LinearSVC) over 50,000 TF-IDF unigram and bigram features.
  - **Stage 2 (Classification)**: One-vs-Rest (OvR) Logistic Regression classifying 8 independent threat vectors.
- **Zero-Hallucination Line Localization**: Static AST pattern matching pinpointing the exact code line, explaining the flaw, and providing verifiable remediation fixes.
- **Audit Reporting**: One-click Markdown Security Audit export and downloadable JSON audit reports.

---

## Project Structure

```text
smart-contract-security-analyzer/
├── server.py              # High-performance FastAPI server & REST API
├── static/                # Modern Web Dashboard (Vanilla CSS + JS)
│   ├── index.html         # Cyber dark UI structure
│   ├── style.css          # Glassmorphic responsive styling & animations
│   └── app.js             # Interactive editor, line highlighting & audit flow
├── predict.py             # Inference pipeline & static AST rule-based checks
├── train_model.py         # Model training script for Linear SVM & OvR Logistic Regression
├── app.py                 # Legacy Streamlit interface (alternative)
├── requirements.txt       # Dependencies (pandas, numpy, scikit-learn, joblib, fastapi, uvicorn)
├── sample_contracts/      # Demonstrative .sol test contracts (Reentrancy, Access Control, Clean, etc.)
└── models/saved/          # Serialized .joblib models and TF-IDF vectorizers
```

---

## Quickstart Guide

### 1. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2. Launch Modern Web Dashboard (Recommended)
```powershell
python server.py
```
Open your browser at: **[http://localhost:8080](http://localhost:8080)**

### 3. Alternative: Launch Legacy Streamlit App
```powershell
streamlit run app.py
```
Open your browser at: **http://localhost:8501**
