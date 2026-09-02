# main.py
"""
AI-Powered Cyber Fraud and Phishing Detection Engine API.
Provides unified REST endpoints for:
1. Browser Extension: POST /api/v1/scan-domain
2. Mobile Android Listener: POST /api/v1/scan-sms
3. Payment Gateway Interceptor: POST /api/v1/scan-payment
"""
import os
import uuid
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
import joblib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Core engine imports
from core.domain_engine import compute_risk_score as compute_domain_risk
from core.sms_engine import compute_sms_risk_score
from payment_engine import compute_payment_risk

# In-memory cross-channel threat session store
# Maps session_token -> smishing threat metadata
threat_sessions: Dict[str, Dict[str, Any]] = {}

# Model artifacts container
models: Dict[str, Any] = {}

def load_all_models():
    print("Loading Machine Learning Models...")
    if os.path.exists("models/domain_xgb.pkl"):
        models["domain"] = joblib.load("models/domain_xgb.pkl")
        print(" -> Domain XGBoost Model Loaded.")
    if os.path.exists("models/sms_clf.pkl"):
        models["sms"] = joblib.load("models/sms_clf.pkl")
        print(" -> SMS Smishing Model Loaded.")
    if os.path.exists("models/payment_risk.pkl"):
        models["payment"] = joblib.load("models/payment_risk.pkl")
        print(" -> Payment Risk Model Loaded.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_all_models()
    yield

# Also load on import for immediate readiness
load_all_models()

app = FastAPI(
    title="AI Cyber Fraud & Phishing Detection Engine",
    description="Cross-channel defense engine connecting Mobile Smishing, Browser Domain Heuristics, and Payment Gateway Interception.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for Chrome Extensions and Web Clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Request & Response Schemas ---

# 1. Domain Request/Response
class DomainScanRequest(BaseModel):
    url: str = Field(..., example="https://secure-login-sbi-update.xyz/verify")
    session_token: Optional[str] = Field(None, description="Optional handover token from Android SMS listener")

class DomainScanResponse(BaseModel):
    url: str
    risk_score: float
    verdict: str
    is_threat: bool
    reasons: List[str]
    action: str
    session_token: Optional[str] = None

# 2. SMS Request/Response
class SMSScanRequest(BaseModel):
    sender: str = Field("UNKNOWN", example="CP-HDFCAC")
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

# 3. Payment Request/Response
class PaymentScanRequest(BaseModel):
    amount: float = Field(..., example=4999.00)
    tx_hour: Optional[int] = Field(14, example=14)
    form_fill_duration: Optional[float] = Field(12.5, example=12.5)
    is_vpn_or_proxy: Optional[bool] = Field(False, example=False)
    velocity_last_10min: Optional[int] = Field(1, example=1)
    device_trust_score: Optional[float] = Field(0.85, example=0.85)
    session_token: Optional[str] = Field(None, description="Smishing handover session token")
    origin_from_sms_lure: Optional[bool] = Field(False, description="Explicit flag or resolved via session_token")
    checkout_url: Optional[str] = Field(None, example="http://hdfc-kyc.top/checkout")
    merchant_vpa: Optional[str] = Field(None, example="hdfc-support@ybl")

class PaymentScanResponse(BaseModel):
    amount: float
    risk_score: float
    verdict: str
    is_fraud: bool
    reasons: List[str]
    action: str
    session_token: Optional[str] = None

# --- API Endpoints ---

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "models_loaded": {
            "domain_model": "domain" in models,
            "sms_model": "sms" in models,
            "payment_model": "payment" in models
        },
        "active_threat_sessions": len(threat_sessions)
    }

# Endpoint 1: Domain Scan (Browser Extension)
@app.post("/api/v1/scan-domain", response_model=DomainScanResponse)
def scan_domain(req: DomainScanRequest):
    domain_model = models.get("domain")
    if domain_model is None:
        raise HTTPException(status_code=503, detail="Domain model is not loaded.")

    url_str = req.url.strip()
    score, reasons = compute_domain_risk(url_str, domain_model)

    # Correlate with active threat session
    if req.session_token and req.session_token in threat_sessions:
        ctx = threat_sessions[req.session_token]
        reasons.append(f"Chained Threat: Launched from flagged SMS sender '{ctx.get('sender', 'Unknown')}'")
        score = max(score, 0.90)

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

# Endpoint 2: SMS Scan (Android Mobile Listener)
@app.post("/api/v1/scan-sms", response_model=SMSScanResponse)
def scan_sms(req: SMSScanRequest):
    sms_bundle = models.get("sms")
    domain_model = models.get("domain")
    if sms_bundle is None:
        raise HTTPException(status_code=503, detail="SMS model is not loaded.")

    result = compute_sms_risk_score(
        text=req.message,
        sms_bundle=sms_bundle,
        domain_model=domain_model,
        sender=req.sender
    )

    session_token = None
    if result["is_threat"]:
        session_token = f"smish_{uuid.uuid4().hex[:10]}"
        threat_sessions[session_token] = {
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

# Endpoint 3: Payment Scan (Payment Gateway Interceptor)
@app.post("/api/v1/scan-payment", response_model=PaymentScanResponse)
def scan_payment(req: PaymentScanRequest):
    payment_model = models.get("payment")
    if payment_model is None:
        raise HTTPException(status_code=503, detail="Payment model is not loaded.")

    # Check if session token links to a flagged SMS smishing lure
    origin_from_sms = req.origin_from_sms_lure
    if req.session_token and req.session_token in threat_sessions:
        origin_from_sms = True

    payload = {
        "amount": req.amount,
        "tx_hour": req.tx_hour,
        "form_fill_duration": req.form_fill_duration,
        "is_vpn_or_proxy": req.is_vpn_or_proxy,
        "velocity_last_10min": req.velocity_last_10min,
        "device_trust_score": req.device_trust_score,
        "origin_from_sms_lure": origin_from_sms
    }

    score, reasons = compute_payment_risk(payload, payment_model)

    # Optional VPA heuristic checks if merchant VPA is provided
    if req.merchant_vpa and "@" in req.merchant_vpa:
        vpa_clean = req.merchant_vpa.lower()
        if any(b in vpa_clean for b in ["hdfc", "sbi", "icici", "paytm", "support"]) and not any(h in vpa_clean for h in ["@razorpay", "@billdesk", "@hdfcbank", "@icici"]):
            reasons.append(f"Suspicious / Impersonated Merchant VPA ({req.merchant_vpa})")
            score = max(score, 0.85)

    is_fraud = score >= 0.50
    verdict = "FRAUD" if is_fraud else "LEGITIMATE"
    action = "DECLINE" if score >= 0.70 else ("CHALLENGE_2FA" if is_fraud else "APPROVE")

    return PaymentScanResponse(
        amount=req.amount,
        risk_score=round(score, 2),
        verdict=verdict,
        is_fraud=is_fraud,
        reasons=reasons,
        action=action,
        session_token=req.session_token
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
