# api/server.py
import os
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
import joblib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core.domain_engine import compute_risk_score as compute_domain_risk
from core.sms_engine import compute_sms_risk_score
from core.gateway_engine import analyze_payment_risk

BASE_DIR = Path(__file__).resolve().parent.parent
DOMAIN_MODEL_PATH = BASE_DIR / "models" / "domain_xgb.pkl"
SMS_MODEL_PATH = BASE_DIR / "models" / "sms_clf.pkl"

SESSION_SMISHING_CACHE: Dict[str, Dict[str, Any]] = {}
models: Dict[str, Any] = {}

def load_models():
    if DOMAIN_MODEL_PATH.exists():
        models["domain"] = joblib.load(DOMAIN_MODEL_PATH)
        print(" -> Domain XGBoost Model Loaded.")
    if SMS_MODEL_PATH.exists():
        models["sms"] = joblib.load(SMS_MODEL_PATH)
        print(" -> SMS Smishing Model Loaded.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_models()
    yield

# Also load on import for fast initialization
load_models()

app = FastAPI(
    title="AI Cyber Fraud & Phishing Detection Engine API",
    description="Backend detection engine for Chrome MV3 Extension, Mobile Smishing Listener, and Payment Gateway Interception.",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Schemas ---

class DomainScanRequest(BaseModel):
    url: str = Field(..., example="https://secure-login-sbi-update.xyz/verify")
    session_token: Optional[str] = Field(None, description="Optional handover token from Android SMS click")

class DomainScanResponse(BaseModel):
    url: str
    risk_score: float
    verdict: str
    is_threat: bool
    reasons: List[str]
    action: str
    session_token: Optional[str] = None

class SMSScanRequest(BaseModel):
    sender: str = Field("UNKNOWN", example="VK-HDFCBK")
    message: str = Field(..., example="Dear customer, your HDFC netbanking is blocked. Update: http://hdfc-kyc.top/auth")

class SMSScanResponse(BaseModel):
    sender: str
    message: str
    risk_score: float
    verdict: str
    is_threat: bool
    sms_ml_score: float
    embedded_urls: List[Dict[str, Any]]
    reasons: List[str]
    action: str
    session_token: Optional[str] = None

class PaymentScanRequest(BaseModel):
    checkout_url: str = Field(..., example="http://cheap-phones-store.xyz/checkout")
    merchant_vpa: str = Field(..., example="amazon-support99@ybl")
    amount: float = Field(..., example=1999.00)
    session_token: Optional[str] = Field(None, description="Smishing handover session token")

class PaymentScanResponse(BaseModel):
    checkout_url: str
    merchant_vpa: str
    amount: float
    risk_score: float
    verdict: str
    is_threat: bool
    reasons: List[str]
    action: str

# --- Endpoints ---

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "domain_model_loaded": "domain" in models,
        "sms_model_loaded": "sms" in models,
        "active_sessions": len(SESSION_SMISHING_CACHE)
    }

@app.post("/api/scan/domain", response_model=DomainScanResponse)
def scan_domain(req: DomainScanRequest):
    domain_model = models.get("domain")
    if domain_model is None:
        raise HTTPException(status_code=503, detail="Domain ML model is not loaded.")

    url_str = req.url.strip()
    score, reasons = compute_domain_risk(url_str, domain_model)

    if req.session_token and req.session_token in SESSION_SMISHING_CACHE:
        smishing_ctx = SESSION_SMISHING_CACHE[req.session_token]
        reasons.append(f"Chained Threat: Opened from smishing SMS sender '{smishing_ctx.get('sender', 'Unknown')}'")
        score = max(score, 0.85)

    is_threat = score >= 0.50
    verdict = "PHISHING" if is_threat else "SAFE"
    action = "BLOCK_PAGE" if score >= 0.70 else ("WARN_USER" if is_threat else "ALLOW")

    return DomainScanResponse(
        url=url_str,
        risk_score=round(score, 2),
        verdict=verdict,
        is_threat=is_threat,
        reasons=reasons,
        action=action,
        session_token=req.session_token
    )

@app.post("/api/scan/sms", response_model=SMSScanResponse)
def scan_sms(req: SMSScanRequest):
    sms_bundle = models.get("sms")
    domain_model = models.get("domain")
    if sms_bundle is None:
        raise HTTPException(status_code=503, detail="SMS ML model is not loaded.")

    result = compute_sms_risk_score(
        text=req.message,
        sms_bundle=sms_bundle,
        domain_model=domain_model,
        sender=req.sender
    )

    session_token = None
    if result["is_threat"]:
        session_token = f"smish_{uuid.uuid4().hex[:10]}"
        SESSION_SMISHING_CACHE[session_token] = {
            "sender": req.sender,
            "message": req.message,
            "risk_score": result["risk_score"],
            "is_threat": True
        }

    return SMSScanResponse(
        sender=result["sender"],
        message=result["message"],
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        is_threat=result["is_threat"],
        sms_ml_score=result["sms_ml_score"],
        embedded_urls=result["embedded_urls"],
        reasons=result["reasons"],
        action=result["action"],
        session_token=session_token
    )

@app.post("/api/scan/payment", response_model=PaymentScanResponse)
def scan_payment(req: PaymentScanRequest):
    domain_model = models.get("domain")
    session_ctx = SESSION_SMISHING_CACHE.get(req.session_token) if req.session_token else None

    result = analyze_payment_risk(
        checkout_url=req.checkout_url,
        merchant_vpa=req.merchant_vpa,
        amount=req.amount,
        domain_model=domain_model,
        session_smishing_context=session_ctx
    )

    return PaymentScanResponse(
        checkout_url=result["checkout_url"],
        merchant_vpa=result["merchant_vpa"],
        amount=result["amount"],
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        is_threat=result["is_threat"],
        reasons=result["reasons"],
        action=result["action"]
    )
