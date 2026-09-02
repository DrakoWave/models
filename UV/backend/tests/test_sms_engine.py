# tests/test_sms_engine.py
import pytest
import joblib
from pathlib import Path

from config import DOMAIN_MODEL_PATH, SMS_MODEL_PATH
from sms_engine import extract_embedded_url, score_sms, get_sms_verdict

BASE_DIR = Path(__file__).resolve().parent.parent

@pytest.fixture(scope="module")
def models():
    d_model = joblib.load(DOMAIN_MODEL_PATH) if DOMAIN_MODEL_PATH.exists() else None
    s_bundle = joblib.load(SMS_MODEL_PATH) if SMS_MODEL_PATH.exists() else None
    return {"domain": d_model, "sms": s_bundle}

def test_extract_embedded_url_various_formats():
    """Verify URL extraction for both http/https and bare smishing domains."""
    assert extract_embedded_url("Meeting at 4pm") is None
    assert extract_embedded_url("Click https://secure-bank.top/auth to verify") == "https://secure-bank.top/auth"
    assert extract_embedded_url("Update pan card at hdfc-kyc.xyz/login today") == "hdfc-kyc.xyz/login"

def test_sms_cross_vector_correlation(models):
    """
    Core cross-channel test:
    An otherwise benign/low-scoring SMS text containing a dangerous phishing URL
    MUST escalate the combined verdict to FRAUD.
    """
    benign_text_with_malicious_link = "Please review your document here: http://hdfc-kyc-verification-login.top/auth"
    
    # 1. Isolated SMS score
    isolated_sms_score = score_sms(benign_text_with_malicious_link, sender="FRIEND", sms_bundle=models["sms"])
    
    # 2. Cross-vector correlation
    verdict_resp = get_sms_verdict(
        text=benign_text_with_malicious_link,
        sender="FRIEND",
        sms_bundle=models["sms"],
        domain_model=models["domain"]
    )
    
    assert verdict_resp.verdict == "FRAUD"
    assert verdict_resp.confidence >= 0.70
    assert len(verdict_resp.reasons) > 0
    assert verdict_resp.detail is not None

def test_raw_phone_number_sender_boost(models):
    """Assert raw phone number sender increases risk compared to an official bank header."""
    text = "Please check your message for new updates."
    res_official = score_sms(text, sender="VM-HDFCBK", sms_bundle=models["sms"])
    res_phone = score_sms(text, sender="+919876543210", sms_bundle=models["sms"])
    
    assert res_phone["probability"] >= res_official["probability"]
    assert any("sender" in r.lower() for r in res_phone["reasons"])

def test_benign_sms_returns_safe(models):
    """Assert genuine transactional and personal SMS messages produce a SAFE verdict."""
    benign_sms = "Dear Customer, INR 3,250.00 debited from A/C XX7812 on 02-Sep. Info: UPI/SWIGGY."
    res = get_sms_verdict(benign_sms, sender="VM-HDFCBK", sms_bundle=models["sms"], domain_model=models["domain"])
    assert res.verdict == "SAFE"
    assert res.confidence < 0.40
    assert res.detail is not None
