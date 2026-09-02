# tests/test_payment_engine.py
import pytest
import joblib
from fastapi.testclient import TestClient

from config import DOMAIN_MODEL_PATH
from payment_engine import check_payment_gateway, KNOWN_FRAUD_UPI_IDS
from main import app

client = TestClient(app)

@pytest.fixture(scope="module")
def domain_model():
    return joblib.load(DOMAIN_MODEL_PATH) if DOMAIN_MODEL_PATH.exists() else None

def test_payment_flags_known_fraud_upi_id(domain_model):
    """Assert payment engine flags known seeded fraud UPI IDs with FRAUD verdict."""
    for fraud_upi in list(KNOWN_FRAUD_UPI_IDS)[:2]:
        res = check_payment_gateway(upi_id=fraud_upi, gateway_url="", domain_model=domain_model)
        assert res.verdict == "FRAUD"
        assert res.confidence == 1.0
        assert len(res.reasons) > 0
        assert res.detail is not None

def test_payment_safe_upi_and_gateway(domain_model):
    """Assert verified UPI and trusted merchant return SAFE."""
    res = check_payment_gateway(
        upi_id="merchant@okaxis",
        gateway_url="https://amazon.in/checkout",
        domain_model=domain_model
    )
    assert res.verdict == "SAFE"
    assert res.confidence < 0.40
    assert res.detail is not None

def test_payment_malicious_gateway_url(domain_model):
    """Assert payment engine flags malicious gateway domains with FRAUD verdict."""
    res = check_payment_gateway(
        upi_id="merchant@okaxis",
        gateway_url="http://hdfc-kyc-verification-login.top/auth",
        domain_model=domain_model
    )
    assert res.verdict == "FRAUD"
    assert res.confidence >= 0.70
    assert len(res.reasons) > 0

def test_all_endpoints_fail_open_without_500_on_malformed_input():
    """
    Non-negotiable requirement:
    No endpoint must ever throw an HTTP 500 on bad, empty, or malformed inputs.
    """
    malformed_payloads = [
        ("/scan-document", {"url": ""}),
        ("/scan-domain", {"url": "http://"}),
        ("/scan-sms", {"message": "", "sender": ""}),
        ("/scan-sms", {"text": "hello"}),
        ("/scan-payment", {"upi_id": "", "gateway_url": ""}),
        ("/health", None)
    ]
    
    for endpoint, payload in malformed_payloads:
        if payload is not None:
            resp = client.post(endpoint, json=payload)
        else:
            resp = client.get(endpoint)
            
        assert resp.status_code == 200, f"Endpoint {endpoint} failed with status {resp.status_code}"
        data = resp.json()
        assert "status" in data or "verdict" in data
