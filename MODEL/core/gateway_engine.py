# core/gateway_engine.py
import re
from typing import Dict, Any, Optional
from core.domain_engine import compute_risk_score as compute_domain_risk, is_trusted_domain

VERIFIED_MERCHANT_HANDLES = {
    "razorpay", "billdesk", "payu", "ccavenue", "hdfcbank", "icici", "sbi", "axisbank"
}

SUSPICIOUS_MERCHANT_PATTERNS = [
    r"support\d*@",
    r"helpdesk\d*@",
    r"refund\d*@",
    r"kyc\d*@",
    r"cashback\d*@",
    r"winner\d*@",
    r"lottery\d*@"
]

def analyze_payment_risk(
    checkout_url: str,
    merchant_vpa: str,
    amount: float,
    domain_model: Any,
    session_smishing_context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    reasons = []
    penalty = 0.0

    url_risk, url_reasons = compute_domain_risk(checkout_url, domain_model)
    if url_risk >= 0.5:
        penalty += 0.55
        reasons.extend(url_reasons)

    vpa_clean = str(merchant_vpa).strip().lower()
    if "@" in vpa_clean:
        username, handle = vpa_clean.split("@", 1)
        brand_spoof = any(b in username for b in ["hdfc", "sbi", "icici", "paytm", "amazon", "flipkart"])
        if brand_spoof and handle not in VERIFIED_MERCHANT_HANDLES:
            penalty += 0.45
            reasons.append(f"Impersonated Brand in Personal UPI ID ({merchant_vpa})")

        for pattern in SUSPICIOUS_MERCHANT_PATTERNS:
            if re.search(pattern, vpa_clean):
                penalty += 0.35
                reasons.append(f"Suspicious VPA Pattern: '{pattern.replace(r'\d*@', '@')}'")
                break
    else:
        penalty += 0.30
        reasons.append("Invalid or Malformed VPA / UPI Address")

    if session_smishing_context and session_smishing_context.get("is_threat"):
        penalty += 0.40
        reasons.append(f"High-Risk Origin: User arrived via Smishing SMS (Session Trigger: {session_smishing_context.get('sender', 'Unknown')})")

    final_score = round(min(1.0, max(url_risk, penalty)), 2)
    is_threat = final_score >= 0.50

    if final_score >= 0.75:
        action = "BLOCK_TRANSACTION"
        verdict = "HIGH_RISK_FRAUD"
    elif is_threat:
        action = "PROMPT_CONFIRMATION"
        verdict = "SUSPICIOUS_PAYMENT"
    else:
        action = "ALLOW"
        verdict = "SAFE"
        if not reasons:
            reasons = ["Verified / Low-Risk Merchant Gateway"]

    return {
        "checkout_url": checkout_url,
        "merchant_vpa": merchant_vpa,
        "amount": amount,
        "risk_score": final_score,
        "verdict": verdict,
        "is_threat": is_threat,
        "reasons": reasons,
        "action": action
    }
