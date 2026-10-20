"""
server.py
---------
FastAPI High-Performance Backend for Smart Contract Security Analyzer.
Replaces the basic Streamlit interface with a rich, modern Web3 audit dashboard.
"""

import os
import re
import json
import time
from pathlib import Path
from typing import Dict, Any, List

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from predict import analyze_solidity_contract, CATEGORY_DISPLAY_NAMES, CATEGORY_KNOWLEDGE

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
SAMPLES_DIR = BASE_DIR / "sample_contracts"

app = FastAPI(
    title="Smart Contract Security Analyzer API",
    description="Machine Learning & AST Rule-Based Vulnerability Detection for Solidity",
    version="2.0.0"
)

# Enable CORS for flexible integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    code: str = Field(..., min_length=1, description="Solidity source code")

SAMPLE_METADATA = [
    {
        "id": "2_reentrancy_vault.sol",
        "title": "Reentrancy Vault",
        "category": "reentrancy",
        "severity": "CRITICAL",
        "description": "State variable updated after external .call transfer violating Checks-Effects-Interactions (CEI).",
        "badge": "Vulnerable"
    },
    {
        "id": "3_access_control_wallet.sol",
        "title": "Access Control Wallet",
        "category": "access_control",
        "severity": "HIGH",
        "description": "Critical fund withdrawal and state change without owner verification checks or relying on tx.origin.",
        "badge": "Vulnerable"
    },
    {
        "id": "4_unchecked_low_level_call.sol",
        "title": "Unchecked Low-Level Call",
        "category": "unchecked_low_calls",
        "severity": "MEDIUM",
        "description": "Ignored boolean return status on low-level .send() or .call() invocations.",
        "badge": "Vulnerable"
    },
    {
        "id": "5_multi_vulnerability_lottery.sol",
        "title": "Multi-Vector Lottery",
        "category": "bad_randomness",
        "severity": "CRITICAL",
        "description": "Complex contract with bad randomness (block.timestamp), unchecked call, and reentrancy vectors.",
        "badge": "Multi-Threat"
    },
    {
        "id": "1_safe_simple_storage.sol",
        "title": "Safe Simple Storage",
        "category": "safe",
        "severity": "CLEAN",
        "description": "Clean, standard Solidity contract with proper state encapsulation and no risky patterns.",
        "badge": "Secure"
    },
    {
        "id": "SecureContract.sol",
        "title": "Secure Vault with CEI",
        "category": "safe",
        "severity": "CLEAN",
        "description": "Secure withdrawal implementing proper zeroing of balance before external interaction.",
        "badge": "Secure"
    },
    {
        "id": "VulnerableContract.sol",
        "title": "Classic Vulnerable Vault",
        "category": "reentrancy",
        "severity": "CRITICAL",
        "description": "Minimal canonical reentrancy pattern for swift demonstration.",
        "badge": "Vulnerable"
    }
]

@app.post("/api/analyze")
async def analyze_contract(payload: AnalyzeRequest):
    code = payload.code.strip()
    if not code:
        raise HTTPException(status_code=400, detail="Solidity source code cannot be empty.")
    
    start_time = time.perf_counter()
    try:
        results = analyze_solidity_contract(code)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(exc)}")
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
    
    # Calculate overall risk score (0 - 100)
    risk_score = 0
    if results["is_vulnerable"]:
        finding_weight = min(len(results.get("verified_mistakes", [])) * 25, 60)
        ml_weight = (results.get("svm_confidence_pct", 50) * 0.4) if results.get("ml_is_vulnerable") else 20
        risk_score = min(int(finding_weight + ml_weight), 99)
    else:
        risk_score = max(5, int(100 - results.get("svm_confidence_pct", 90)))
    
    # Count lines and code stats
    lines = code.splitlines()
    loc = len(lines)
    sloc = len([l for l in lines if l.strip() and not l.strip().startswith("//") and not l.strip().startswith("/*")])

    response_payload = {
        **results,
        "execution_time_ms": elapsed_ms,
        "risk_score": risk_score,
        "loc": loc,
        "sloc": sloc,
        "category_metadata": CATEGORY_KNOWLEDGE
    }
    return JSONResponse(content=response_payload)

@app.get("/api/samples")
async def list_samples():
    """List available sample contracts with rich tags."""
    return JSONResponse(content=SAMPLE_METADATA)

@app.get("/api/samples/{filename}")
async def get_sample_content(filename: str):
    """Retrieve full Solidity code for a given sample contract."""
    # Sanitize filename
    clean_name = os.path.basename(filename)
    target_path = SAMPLES_DIR / clean_name
    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(status_code=404, detail="Sample contract not found.")
    
    try:
        content = target_path.read_text(encoding="utf-8")
        return {"filename": clean_name, "code": content}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read contract: {str(exc)}")

BLOCKSCOUT_NETWORKS = {
    "mainnet": {"name": "Ethereum Mainnet", "base_url": "https://eth.blockscout.com", "chain_id": 1},
    "sepolia": {"name": "Sepolia Testnet", "base_url": "https://eth-sepolia.blockscout.com", "chain_id": 11155111},
    "base": {"name": "Base Mainnet", "base_url": "https://base.blockscout.com", "chain_id": 8453},
    "arbitrum": {"name": "Arbitrum One", "base_url": "https://arbitrum.blockscout.com", "chain_id": 42161},
    "optimism": {"name": "Optimism Mainnet", "base_url": "https://optimism.blockscout.com", "chain_id": 10},
    "polygon": {"name": "Polygon PoS", "base_url": "https://polygon.blockscout.com", "chain_id": 137},
    "gnosis": {"name": "Gnosis Chain", "base_url": "https://gnosis.blockscout.com", "chain_id": 100},
}

ETH_ADDRESS_REGEX = re.compile(r"^0x[a-fA-F0-9]{40}$")

def parse_etherscan_source(raw_source: str) -> str:
    """Handle standard single-file or JSON-wrapped multi-file Etherscan source payloads."""
    raw = raw_source.strip()
    if raw.startswith("{{") and raw.endswith("}}"):
        raw = raw[1:-1]
    if raw.startswith("{") and raw.endswith("}"):
        try:
            parsed = json.loads(raw)
            sources = parsed.get("sources", {})
            if sources:
                parts = []
                for fname, fcontent in sources.items():
                    content_str = fcontent.get("content", "")
                    parts.append(f"// ==========================================\n// File: {fname}\n// ==========================================\n{content_str}")
                return "\n\n".join(parts)
        except Exception:
            pass
    return raw

@app.get("/api/fetch-contract")
async def fetch_verified_contract(
    address: str,
    network: str = "mainnet",
    api_key: str = "",
    use_etherscan: bool = False
):
    """
    Fetch verified Solidity source code directly by contract address.
    Supports Blockscout (zero-config, free public explorer) and Etherscan API V2.
    """
    clean_addr = address.strip()
    if not ETH_ADDRESS_REGEX.match(clean_addr):
        raise HTTPException(
            status_code=400,
            detail="Invalid Ethereum contract address format. Expected a 42-character hex address starting with 0x (e.g., 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2)."
        )

    net_key = network.lower().strip()
    if net_key not in BLOCKSCOUT_NETWORKS:
        valid_nets = ", ".join(BLOCKSCOUT_NETWORKS.keys())
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported network '{network}'. Supported networks: {valid_nets}"
        )

    net_info = BLOCKSCOUT_NETWORKS[net_key]

    # Check if Etherscan API key is provided
    etherscan_key = api_key.strip() or os.getenv("ETHERSCAN_API_KEY", "").strip()
    if use_etherscan and etherscan_key:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                url = "https://api.etherscan.io/v2/api"
                params = {
                    "chainid": net_info["chain_id"],
                    "module": "contract",
                    "action": "getsourcecode",
                    "address": clean_addr,
                    "apikey": etherscan_key
                }
                resp = await client.get(url, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "1" and data.get("result"):
                        result = data["result"][0]
                        contract_name = result.get("ContractName", "Contract")
                        raw_source = result.get("SourceCode", "")
                        if raw_source:
                            source_code = parse_etherscan_source(raw_source)
                            return {
                                "source": "etherscan",
                                "network": net_info["name"],
                                "network_key": net_key,
                                "address": clean_addr,
                                "contract_name": contract_name,
                                "compiler_version": result.get("CompilerVersion", "Unknown"),
                                "optimization_used": result.get("OptimizationUsed", "0") == "1",
                                "code": source_code,
                                "files_count": 1
                            }
        except Exception:
            # Fall back to Blockscout seamlessly
            pass

    # Blockscout public explorer lookup
    blockscout_url = f"{net_info['base_url']}/api/v2/smart-contracts/{clean_addr}"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(blockscout_url)
            if resp.status_code == 404:
                raise HTTPException(
                    status_code=404,
                    detail=f"Contract at {clean_addr} was not found or is not verified on {net_info['name']}."
                )
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=resp.status_code,
                    detail=f"Explorer returned HTTP {resp.status_code}: {resp.text[:180]}"
                )

            data = resp.json()
            main_code = data.get("source_code", "")
            additional = data.get("additional_sources", []) or []

            if not main_code and not additional:
                raise HTTPException(
                    status_code=404,
                    detail=f"No verified Solidity source code available for {clean_addr} on {net_info['name']}."
                )

            contract_name = data.get("name") or "VerifiedContract"

            if additional:
                assembled_sources = []
                file_path = data.get("file_path") or f"{contract_name}.sol"
                assembled_sources.append(f"// ==========================================\n// Main Contract: {file_path}\n// ==========================================\n{main_code}")
                for item in additional:
                    item_path = item.get("file_path", "dependency.sol")
                    item_code = item.get("source_code", "")
                    assembled_sources.append(f"// ==========================================\n// Dependency: {item_path}\n// ==========================================\n{item_code}")
                combined_code = "\n\n".join(assembled_sources)
            else:
                combined_code = main_code

            return {
                "source": "blockscout",
                "network": net_info["name"],
                "network_key": net_key,
                "address": clean_addr,
                "contract_name": contract_name,
                "compiler_version": data.get("compiler_version", "Unknown"),
                "evm_version": data.get("evm_version", "Default"),
                "optimization_enabled": data.get("optimization_enabled", False),
                "code": combined_code,
                "files_count": 1 + len(additional),
                "explorer_url": f"{net_info['base_url']}/address/{clean_addr}"
            }
    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail=f"Request to {net_info['name']} timed out. Please try again.")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch contract: {str(exc)}")

@app.get("/api/model-info")
async def model_info():
    """Return machine learning model architecture details."""
    return {
        "title": "Machine Learning-Based Smart Contract Vulnerability Detection & Classification",
        "binary_detector": {
            "model": "Linear Support Vector Machine (LinearSVC)",
            "features": "TF-IDF Unigrams & Bigrams (50,000 features max)",
            "task": "Binary Vulnerability Detection (Clean = 0, Vulnerable = 1)",
            "decision_boundary_metric": "Euclidean signed distance to hyperplane"
        },
        "multilabel_classifier": {
            "model": "One-vs-Rest Logistic Regression (8 Independent Classifiers)",
            "features": "TF-IDF Lexical Tokens",
            "categories": [CATEGORY_DISPLAY_NAMES[c] for c in CATEGORY_DISPLAY_NAMES]
        },
        "static_checker": {
            "engine": "AST Token & Regex Rule-Based Pattern Verification",
            "capability": "Exact line-level localization, coding mistake explanation, and patch generation"
        }
    }

# Mount static directory for the front-end SPA
if not STATIC_DIR.exists():
    STATIC_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Smart Contract Security Analyzer API is active. Static UI initializing."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8080, reload=True)
