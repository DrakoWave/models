# payment_engine.py
"""
Payment Gateway and UPI Fraud Interception Engine.
"""
import logging
from typing import Set, Any, List
from schemas import ScanVerdictResponse
import domain_engine

logger = logging.getLogger(__name__)

# Hackathon-seeded placeholder database of reported malicious UPI IDs
KNOWN_FRAUD_UPI_IDS: Set[str] = {
    "fraudster123@upi",
    "scamvictim@ybl",
    "fakekyc@okaxis",
    "lotterywinner@paytm",
    "urgentrefund@ibl"
}

def check_payment_gateway(
    upi_id: str,
    gateway_url: str,
    domain_model: Any
) -> ScanVerdictResponse:
    """
    Evaluates UPI identifiers and payment gateway URLs for fraudulent patterns.
    Takes the higher-risk verdict between UPI lookup and gateway domain analysis.
    """
    try:
        upi_clean = str(upi_id or "").strip().lower()
        gateway_clean = str(gateway_url or "").strip()
        reasons: List[str] = []
        confidence = 0.0
        verdict = "SAFE"
        detail = "Payment gateway and recipient verified clean"

        # Signal 1: Reported Malicious UPI ID Lookup
        if upi_clean and upi_clean in KNOWN_FRAUD_UPI_IDS:
            reasons.append(f"Reported malicious recipient UPI ID ({upi_clean})")
            confidence = 1.0
            verdict = "FRAUD"
            detail = "Direct transfer to blacklisted fraudulent UPI VPA"

        # Signal 2: Gateway URL Domain Heuristics & ML
        if gateway_clean:
            gateway_verdict = domain_engine.get_domain_verdict(gateway_clean, domain_model)
            if gateway_verdict.confidence > confidence:
                confidence = gateway_verdict.confidence
                verdict = gateway_verdict.verdict
                detail = f"High-risk checkout gateway ({gateway_verdict.detail})"
            for r in gateway_verdict.reasons:
                reasons.append(f"Gateway host: {r}")

        unique_reasons = list(dict.fromkeys(reasons)) if confidence > 0.40 else []

        return ScanVerdictResponse(
            verdict=verdict,
            confidence=round(float(confidence), 2),
            reasons=unique_reasons,
            detail=detail
        )
    except Exception as e:
        logger.error(f"Unexpected error in check_payment_gateway: {e}")
        return ScanVerdictResponse(
            verdict="SAFE",
            confidence=0.0,
            reasons=[],
            detail="Scan completed with fail-open fallback"
        )
