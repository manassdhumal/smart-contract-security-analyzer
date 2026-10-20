"""
predict.py
----------
Prediction and Basic Code-Pattern Explanation module for Solidity Smart Contracts.

What this file does:
1. Loads the saved Linear SVM model, One-vs-Rest Logistic Regression model, and TF-IDF vectorizers.
2. Preprocesses raw Solidity source code using the same steps as `train_model.py`.
3. Predicts whether the contract is potentially vulnerable using Linear SVM.
4. Predicts the specific vulnerability categories using One-vs-Rest Logistic Regression.
5. Runs a clear, documented set of basic Solidity code-pattern checks to find exact line numbers,
   explain the coding mistake when evidence exists, and suggest security fixes.
6. Never invents vulnerable line numbers or root causes.
7. Returns all results in a simple Python dictionary.
"""

import math
import re
from pathlib import Path

import joblib

from train_model import MODELS_DIR, VULNERABILITY_CATEGORIES, preprocess_solidity_code

# Human-readable names for the 8 vulnerability categories
CATEGORY_DISPLAY_NAMES = {
    "access_control": "Access Control",
    "arithmetic": "Arithmetic Vulnerabilities",
    "bad_randomness": "Bad Randomness",
    "denial_service": "Denial of Service",
    "front_running": "Front Running",
    "reentrancy": "Reentrancy",
    "time_manipulation": "Time Manipulation",
    "unchecked_low_calls": "Unchecked Low-Level Calls",
}

# Explanations and suggested solutions for each of the 8 categories
CATEGORY_KNOWLEDGE = {
    "reentrancy": {
        "why_vulnerable": (
            "The contract transfers Ether or calls an external contract before updating its own internal state "
            "(such as setting user balances to zero). An untrusted external contract can re-enter the function "
            "and drain funds repeatedly."
        ),
        "suggested_solution": (
            "Follow the Checks-Effects-Interactions (CEI) pattern: update all state variables (e.g., `balances[msg.sender] = 0`) "
            "BEFORE making external `.call` transfers, or add OpenZeppelin's `nonReentrant` modifier."
        ),
    },
    "access_control": {
        "why_vulnerable": (
            "Critical administrative actions (such as withdrawing funds, changing ownership, `delegatecall`, or `selfdestruct`) "
            "either lack proper `msg.sender` authorization checks or rely on `tx.origin`, which is vulnerable to phishing."
        ),
        "suggested_solution": (
            "Use `require(msg.sender == owner, 'Not authorized')` or OpenZeppelin's `onlyOwner` modifier instead of `tx.origin`, "
            "and restrict all sensitive functions (`delegatecall`, `selfdestruct`, treasury withdrawals) to trusted roles."
        ),
    },
    "arithmetic": {
        "why_vulnerable": (
            "In Solidity versions older than `0.8.0`, integer addition, subtraction, and multiplication can silently overflow "
            "or underflow without reverting if `SafeMath` is not used."
        ),
        "suggested_solution": (
            "Upgrade the compiler to Solidity `^0.8.0` (which includes built-in overflow/underflow checks) or use "
            "OpenZeppelin's `SafeMath` library for all arithmetic operations in legacy contracts."
        ),
    },
    "unchecked_low_calls": {
        "why_vulnerable": (
            "Low-level Solidity calls like `.send()` and `.call()` return a boolean `false` when they fail instead of "
            "automatically reverting the transaction. Ignoring this return value causes the contract to continue as if the payment succeeded."
        ),
        "suggested_solution": (
            "Always capture and verify the return value of low-level calls using `require(success, 'Transfer failed')`."
        ),
    },
    "bad_randomness": {
        "why_vulnerable": (
            "The contract generates random numbers using predictable on-chain block variables like `block.timestamp`, "
            "`blockhash`, or `block.difficulty`. Attackers or miners can predict the outcome in advance."
        ),
        "suggested_solution": (
            "Use a verifiable off-chain randomness oracle such as Chainlink VRF, or implement a cryptographic Commit-Reveal scheme."
        ),
    },
    "time_manipulation": {
        "why_vulnerable": (
            "The contract relies on `block.timestamp` (or `now`) for critical conditions. Miners/validators can slightly "
            "manipulate the block timestamp to influence time-sensitive logic."
        ),
        "suggested_solution": (
            "Avoid using `block.timestamp` or `now` for tight time constraints or randomness; allow a safe time buffer "
            "of at least several minutes for time-locks."
        ),
    },
    "denial_service": {
        "why_vulnerable": (
            "Making external Ether transfers or contract calls inside a `for`/`while` loop allows a single failing recipient "
            "or high gas consumption to revert the entire transaction and block all other users."
        ),
        "suggested_solution": (
            "Replace loop-based push payments with a Pull-Payment pattern where users withdraw their own funds individually."
        ),
    },
    "front_running": {
        "why_vulnerable": (
            "Transactions waiting in the public Ethereum mempool can be seen by bots, which can submit a competing transaction "
            "with a higher gas fee to execute before the original user's transaction."
        ),
        "suggested_solution": (
            "Use a two-step Commit-Reveal pattern to hide sensitive inputs until committed, or enforce slippage limits on trades."
        ),
    },
}

# Small, clearly documented set of basic Solidity code-pattern checks
BASIC_CODE_PATTERNS = [
    {
        "category": "reentrancy",
        "pattern_name": "External Value Call (.call{value: ...} or .call.value(...))",
        "regex": r"\.\s*call\s*(\{\s*value\s*:|\.value\s*\()",
        "mistake_explanation": (
            "Uses a low-level `.call` to send Ether. When placed before updating the user's balance in storage, "
            "an external contract's fallback function can re-enter and withdraw funds again."
        ),
    },
    {
        "category": "access_control",
        "pattern_name": "Authorization Using tx.origin",
        "regex": r"\btx\.origin\b",
        "mistake_explanation": (
            "Uses `tx.origin` for caller checks instead of `msg.sender`. If the owner interacts with a malicious "
            "contract, that contract can forward the call and pass the `tx.origin == owner` check."
        ),
    },
    {
        "category": "access_control",
        "pattern_name": "Low-Level delegatecall Usage",
        "regex": r"\.\s*delegatecall\s*\(",
        "mistake_explanation": (
            "Executes external contract code inside this contract's storage context via `delegatecall`. "
            "If untrusted users can call this or control the target address, they can overwrite contract ownership."
        ),
    },
    {
        "category": "access_control",
        "pattern_name": "Contract Destruction (selfdestruct / suicide)",
        "regex": r"\b(selfdestruct|suicide)\s*\(",
        "mistake_explanation": (
            "Contains `selfdestruct` (or `suicide`), which permanently destroys the contract and forces its Ether balance "
            "to a target address if not strictly protected by `onlyOwner`."
        ),
    },
    {
        "category": "unchecked_low_calls",
        "pattern_name": "Unchecked .send() or .call() Return Value",
        "regex": r"^\s*(?!require\b|if\b|bool\b|\(\s*bool\b).*?\.\s*(send|call)\s*(\(|{)",
        "mistake_explanation": (
            "Calls `.send()` or `.call()` without assigning or checking the boolean return value (`require(success)`). "
            "If the transfer fails, execution continues silently."
        ),
    },
    {
        "category": "bad_randomness",
        "pattern_name": "On-Chain Randomness via Block Attributes",
        "regex": r"\b(blockhash|block\.difficulty|block\.prevrandao)\b|keccak256\s*\([^;]*\b(block\.timestamp|now|block\.number)\b",
        "mistake_explanation": (
            "Computes pseudo-random values from public block variables (`block.timestamp`, `blockhash`, `block.number`), "
            "which can be predicted by other contracts in the same block."
        ),
    },
    {
        "category": "time_manipulation",
        "pattern_name": "Timestamp Dependence (block.timestamp / now)",
        "regex": r"\b(block\.timestamp|now)\b",
        "mistake_explanation": (
            "Relies on `block.timestamp` or `now`, which block proposers can shift slightly to manipulate time-based conditions."
        ),
    },
    {
        "category": "arithmetic",
        "pattern_name": "Legacy Solidity Compiler (< 0.8.0) Without Built-In Overflow Checks",
        "regex": r"\bpragma\s+solidity\s+[\^~><=\s]*0\.[4567]\.",
        "mistake_explanation": (
            "Uses a Solidity compiler version prior to `0.8.0` where integer arithmetic does not automatically check "
            "for overflow or underflow."
        ),
    },
    {
        "category": "denial_service",
        "pattern_name": "External Transfer Inside a Loop",
        "regex": r"\bfor\s*\([^)]*\)",
        "mistake_explanation": (
            "Contains a `for` loop alongside external transfers. If one recipient account reverts on receiving Ether, "
            "the entire loop reverts and causes a Denial of Service."
        ),
    },
]


def strip_comments_preserve_lines(source_code):
    """
    Remove single-line (//) and block (/* ... */) comments while keeping
    the exact same number of lines so line numbers remain 100% accurate.
    """
    raw_lines = source_code.splitlines()
    cleaned_lines = []
    in_block_comment = False

    for raw_line in raw_lines:
        line_clean = raw_line

        if in_block_comment:
            if "*/" in line_clean:
                in_block_comment = False
                line_clean = line_clean.split("*/", 1)[1]
            else:
                cleaned_lines.append("")
                continue

        while "/*" in line_clean:
            before, after = line_clean.split("/*", 1)
            if "*/" in after:
                line_clean = before + " " + after.split("*/", 1)[1]
            else:
                line_clean = before
                in_block_comment = True
                break

        # Strip single-line comment //
        line_clean = line_clean.split("//", 1)[0]
        cleaned_lines.append(line_clean)

    return raw_lines, cleaned_lines


def check_missing_owner_authorization(raw_lines, cleaned_lines):
    """
    Check for missing owner authorization in `changeOwner()` (or ownership-changing functions).
    Specifically checks if `function changeOwner(...)` modifies `owner = ...` without:
    - an authorization modifier like `onlyOwner` in the function header, OR
    - an explicit caller check like `require(msg.sender == owner, ...)` or `if (msg.sender != owner)` in the body.
    """
    findings = []
    num_lines = len(cleaned_lines)

    for i in range(num_lines):
        line_clean = cleaned_lines[i]
        # Match function changeOwner(...) declaration
        if re.search(r"\bfunction\s+changeOwner\s*\(", line_clean):
            func_start_line = i + 1

            # Collect the function block from opening '{' to matching '}'
            brace_depth = 0
            found_open_brace = False
            func_end_idx = i

            for j in range(i, num_lines):
                for ch in cleaned_lines[j]:
                    if ch == "{":
                        brace_depth += 1
                        found_open_brace = True
                    elif ch == "}":
                        brace_depth -= 1
                if found_open_brace and brace_depth <= 0:
                    func_end_idx = j
                    break

            func_clean_block = "\n".join(cleaned_lines[i : func_end_idx + 1])
            func_raw_block = "\n".join(
                f"Line {line_no}: {raw_lines[line_no - 1]}"
                for line_no in range(func_start_line, func_end_idx + 2)
            )

            # Check if the function has an owner authorization check or modifier
            has_only_owner_modifier = bool(re.search(r"\bonlyOwner\b", func_clean_block, flags=re.IGNORECASE))
            has_msg_sender_owner_check = bool(
                re.search(
                    r"(require|if)\s*\([^;{}]*\bmsg\.sender\b[^;{}]*\bowner\b|"
                    r"(require|if)\s*\([^;{}]*\bowner\b[^;{}]*\bmsg\.sender\b",
                    func_clean_block,
                )
            )

            if not (has_only_owner_modifier or has_msg_sender_owner_check):
                # Find the exact line where `owner = ...` is assigned, or default to function declaration line
                assignment_line = func_start_line
                for k in range(i, func_end_idx + 1):
                    if re.search(r"\bowner\s*=\s*", cleaned_lines[k]):
                        assignment_line = k + 1
                        break

                findings.append(
                    {
                        "line_number": func_start_line,
                        "assignment_line": assignment_line,
                        "code_line": func_raw_block,
                        "category_key": "access_control",
                        "category_name": CATEGORY_DISPLAY_NAMES["access_control"],
                        "pattern_name": "Missing Owner Authorization in changeOwner()",
                        "coding_mistake": (
                            f"`function changeOwner()` (lines {func_start_line}–{func_end_idx + 1}) updates `owner` "
                            f"on line {assignment_line} without checking `require(msg.sender == owner)` or applying "
                            f"an `onlyOwner` modifier. Anyone can call `changeOwner()` and take over contract ownership."
                        ),
                        "suggested_fix": (
                            "Add `require(msg.sender == owner, \"Only owner can change owner\");` at the start of "
                            "`changeOwner()`, or restrict the function with an `onlyOwner` modifier."
                        ),
                    }
                )

    return findings


def check_basic_code_patterns(source_code):
    """
    Scan the original Solidity code line by line (ignoring comments) to find
    verified line numbers for our documented code patterns, plus function-level
    missing owner authorization in `changeOwner()`.
    Never invents line numbers.
    """
    raw_lines, cleaned_lines = strip_comments_preserve_lines(source_code)
    verified_findings = []

    # 1. Check for missing owner authorization in changeOwner()
    verified_findings.extend(check_missing_owner_authorization(raw_lines, cleaned_lines))

    # 2. Check line-by-line regex rules
    for line_idx, line_clean in enumerate(cleaned_lines):
        if not line_clean.strip():
            continue

        line_number = line_idx + 1
        raw_line = raw_lines[line_idx]

        for rule in BASIC_CODE_PATTERNS:
            if re.search(rule["regex"], line_clean, flags=re.IGNORECASE):
                # For loop DoS, only flag if .transfer, .send, or .call appears near the loop
                if rule["category"] == "denial_service":
                    nearby = "\n".join(cleaned_lines[line_idx : min(len(cleaned_lines), line_idx + 10)])
                    if not re.search(r"\.\s*(transfer|send|call)\b", nearby):
                        continue

                verified_findings.append(
                    {
                        "line_number": line_number,
                        "code_line": f"Line {line_number}: {raw_line.strip()}",
                        "category_key": rule["category"],
                        "category_name": CATEGORY_DISPLAY_NAMES[rule["category"]],
                        "pattern_name": rule["pattern_name"],
                        "coding_mistake": rule["mistake_explanation"],
                        "suggested_fix": CATEGORY_KNOWLEDGE[rule["category"]]["suggested_solution"],
                    }
                )

    return verified_findings


def load_saved_models():
    """Load the trained Linear SVM, One-vs-Rest Logistic Regression, and TF-IDF vectorizers."""
    binary_tfidf = joblib.load(MODELS_DIR / "binary_tfidf.joblib")
    svm_model = joblib.load(MODELS_DIR / "linear_svm.joblib")
    multilabel_tfidf = joblib.load(MODELS_DIR / "multilabel_tfidf.joblib")
    multilabel_bundle = joblib.load(MODELS_DIR / "multilabel_ovr_lr.joblib")

    if isinstance(multilabel_bundle, dict):
        ovr_model = multilabel_bundle["classifier"]
        categories = multilabel_bundle.get("categories", VULNERABILITY_CATEGORIES)
    else:
        ovr_model = multilabel_bundle
        categories = VULNERABILITY_CATEGORIES

    return binary_tfidf, svm_model, multilabel_tfidf, ovr_model, categories


def analyze_solidity_contract(source_code):
    """
    Main prediction function called by `app.py`.
    Accepts raw Solidity source code and returns a simple Python dictionary with:
    - Overall detection status (combining ML + Rule-based checks)
    - Separate ML binary prediction (Linear SVM) and Multi-Label probabilities (Logistic Regression)
    - Separate Rule-based code-pattern findings (including missing authorization in changeOwner())
    - Reasons, verified code lines, and suggested security fixes
    """
    if not source_code or not source_code.strip():
        return {"error": "Please provide Solidity smart contract code to analyze."}

    # 1. Load trained models
    binary_tfidf, svm_model, multilabel_tfidf, ovr_model, categories = load_saved_models()

    # 2. Preprocess Solidity code using the exact same function as train_model.py
    cleaned_code = preprocess_solidity_code(source_code)
    X_binary = binary_tfidf.transform([cleaned_code])
    X_multi = multilabel_tfidf.transform([cleaned_code])

    # 3. Binary Prediction using Linear SVM (0 = Clean, 1 = Vulnerable)
    svm_pred = int(svm_model.predict(X_binary)[0])
    svm_score = float(svm_model.decision_function(X_binary)[0])
    # Confidence proxy from Equation (4) of the research paper: 1 / (1 + exp(-|s|))
    svm_confidence = round((1.0 / (1.0 + math.exp(-abs(svm_score)))) * 100.0, 2)
    ml_is_vulnerable = bool(svm_pred == 1)

    # 4. Multi-Label Vulnerability Classification using One-vs-Rest Logistic Regression
    probs = ovr_model.predict_proba(X_multi)[0]
    ml_predicted_categories = []
    category_probabilities = {}

    for idx, cat_key in enumerate(categories):
        prob_pct = round(float(probs[idx]) * 100.0, 2)
        display_name = CATEGORY_DISPLAY_NAMES.get(cat_key, cat_key)
        category_probabilities[display_name] = prob_pct
        if probs[idx] >= 0.50 and ml_is_vulnerable:
            ml_predicted_categories.append(cat_key)

    if ml_is_vulnerable and not ml_predicted_categories:
        top_idx = int(probs.argmax())
        ml_predicted_categories.append(categories[top_idx])

    # 5. Run Rule-Based Solidity Code-Pattern Checks (independent of SVM prediction)
    verified_mistakes = check_basic_code_patterns(source_code)
    rule_based_vulnerable = len(verified_mistakes) > 0
    pattern_categories = [item["category_key"] for item in verified_mistakes]

    # Combine categories identified by ML or Rule-Based Pattern Checks
    all_detected_keys = []
    for cat_key in categories:
        if cat_key in ml_predicted_categories or cat_key in pattern_categories:
            all_detected_keys.append(cat_key)

    # Final combined verdict: Flag as Potentially Vulnerable if EITHER ML or Rule-Based check finds an issue
    is_vulnerable = ml_is_vulnerable or rule_based_vulnerable
    status_text = "Potentially Vulnerable" if is_vulnerable else "No Vulnerability Detected"

    # Build human-readable explanations and solutions
    vulnerability_type_names = [CATEGORY_DISPLAY_NAMES[k] for k in all_detected_keys]
    why_vulnerable_list = []
    suggested_solutions_list = []

    for item in verified_mistakes:
        why_vulnerable_list.append(f"**{item['category_name']} ({item['pattern_name']}):** {item['coding_mistake']}")
        fix_text = f"**{item['category_name']} Fix:** {item['suggested_fix']}"
        if fix_text not in suggested_solutions_list:
            suggested_solutions_list.append(fix_text)

    for k in all_detected_keys:
        if k not in pattern_categories:
            cat_name = CATEGORY_DISPLAY_NAMES[k]
            info = CATEGORY_KNOWLEDGE[k]
            why_vulnerable_list.append(f"**{cat_name} (ML Prediction):** {info['why_vulnerable']}")
            fix_text = f"**{cat_name} Fix:** {info['suggested_solution']}"
            if fix_text not in suggested_solutions_list:
                suggested_solutions_list.append(fix_text)

    # Explain clearly whether ML and Rule-based checks agreed or differed
    if rule_based_vulnerable and not ml_is_vulnerable:
        mistake_summary = (
            f"Rule-based code analysis verified {len(verified_mistakes)} vulnerability pattern(s) with exact line numbers "
            f"(Note: The TF-IDF Linear SVM model predicted 'Clean (0)' because this short snippet contains mostly standard "
            f"tokens, demonstrating why rule-based pattern checks are combined with ML)."
        )
    elif is_vulnerable and not rule_based_vulnerable:
        mistake_summary = (
            "Potential vulnerability detected by the ML model based on lexical token patterns. "
            "Exact line number and root cause require manual code verification."
        )
    elif is_vulnerable:
        mistake_summary = f"Both the ML model and rule-based analysis flagged this contract ({len(verified_mistakes)} verified pattern(s))."
    else:
        mistake_summary = "No suspicious coding mistakes or vulnerability patterns were detected by either ML or rule-based checks."

    return {
        "error": None,
        "status": status_text,
        "is_vulnerable": is_vulnerable,
        "ml_is_vulnerable": ml_is_vulnerable,
        "ml_binary_prediction": "Vulnerable (1)" if ml_is_vulnerable else "Not Vulnerable / Clean (0)",
        "ml_predicted_categories": [CATEGORY_DISPLAY_NAMES[k] for k in ml_predicted_categories]
        if ml_predicted_categories
        else ["None (SVM predicted Clean)"],
        "rule_based_vulnerable": rule_based_vulnerable,
        "rule_based_status": (
            f"Potentially Vulnerable ({len(verified_mistakes)} finding(s))"
            if rule_based_vulnerable
            else "No Rule-Based Issues Found"
        ),
        "svm_decision_score": round(svm_score, 4),
        "svm_confidence_pct": svm_confidence,
        "vulnerability_types": vulnerability_type_names if vulnerability_type_names else ["None Detected"],
        "category_probabilities": category_probabilities,
        "why_vulnerable": why_vulnerable_list
        if why_vulnerable_list
        else ["Neither the machine learning model nor the rule-based code checker found known vulnerability risks."],
        "mistake_summary": mistake_summary,
        "verified_mistakes": verified_mistakes,
        "suggested_solutions": suggested_solutions_list
        if suggested_solutions_list
        else ["No immediate code changes required. Owner authorization is properly enforced."],
        "model_used": (
            "Binary Detection: Linear SVM (TF-IDF 50,000 features) | "
            "Category Classification: One-vs-Rest Logistic Regression (8 categories) | "
            "Static Verification: Rule-Based Solidity Code-Pattern Checker"
        ),
    }
