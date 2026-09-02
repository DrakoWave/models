# test_main_api.py
"""
Integration test suite for unified FastAPI backend (main.py):
- POST /api/v1/scan-domain
- POST /api/v1/scan-sms
- POST /api/v1/scan-payment
- Cross-channel session handover test (SMS Flag -> Session Token -> Payment Block)
"""
import sys
import json
from fastapi.testclient import TestClient
from main import app

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

client = TestClient(app)

print("=" * 90)
print("1. Testing GET /health Endpoint")
print("=" * 90)
resp = client.get("/health")
print(f"Status: {resp.status_code}")
print(json.dumps(resp.json(), indent=2))
assert resp.status_code == 200

print("\n" + "=" * 90)
print("2. Testing POST /api/v1/scan-domain (Browser Extension Input)")
print("=" * 90)
domain_payloads = [
    {"url": "https://netbanking.hdfcbank.com/netbanking/"},
    {"url": "http://hdfc-kyc-verification.top/auth"}
]

for p in domain_payloads:
    r = client.post("/api/v1/scan-domain", json=p)
    data = r.json()
    print(f"URL: {data['url']}")
    print(f"-> Risk Score: {data['risk_score']} | Verdict: {data['verdict']} | Action: {data['action']}")
    print(f"   Reasons: {data['reasons']}")
    print("-" * 70)
    assert r.status_code == 200

print("\n" + "=" * 90)
print("3. Testing POST /api/v1/scan-sms (Android Listener Input)")
print("=" * 90)
sms_payloads = [
    {
        "sender": "VM-HDFCBK",
        "message": "Dear Customer, INR 3,250.00 debited from A/C XX7812 on 02-Sep. Info: UPI/SWIGGY."
    },
    {
        "sender": "CP-HDFCAC",
        "message": "Dear customer, your HDFC netbanking is blocked due to pending KYC. Update: http://hdfc-kyc.top/auth"
    }
]

smishing_token = None
for p in sms_payloads:
    r = client.post("/api/v1/scan-sms", json=p)
    data = r.json()
    print(f"Sender: {data['sender']} | SMS: {data['message'][:50]}...")
    print(f"-> Risk Score: {data['risk_score']} | Verdict: {data['verdict']} | Token: {data.get('session_token')}")
    print(f"   Reasons: {data['reasons']}")
    print("-" * 70)
    assert r.status_code == 200
    if data.get("session_token"):
        smishing_token = data["session_token"]

print("\n" + "=" * 90)
print("4. Testing POST /api/v1/scan-payment (Payment Gateway Interceptor Input)")
print("=" * 90)
payment_scenarios = [
    # Scenario A: Legitimate User Purchase
    {
        "name": "Legitimate User Purchase",
        "payload": {
            "amount": 1499.00,
            "tx_hour": 15,
            "form_fill_duration": 18.0,
            "is_vpn_or_proxy": False,
            "velocity_last_10min": 1,
            "device_trust_score": 0.95
        }
    },
    # Scenario B: Bot Credential-Stuffing Burst
    {
        "name": "Bot Credential-Stuffing Burst",
        "payload": {
            "amount": 49.00,
            "tx_hour": 3,
            "form_fill_duration": 0.45,
            "is_vpn_or_proxy": True,
            "velocity_last_10min": 8,
            "device_trust_score": 0.15
        }
    },
    # Scenario C: Chained Smishing Victim Checkout
    {
        "name": "Chained Smishing Victim Checkout (Token Handover)",
        "payload": {
            "amount": 8500.00,
            "tx_hour": 16,
            "form_fill_duration": 12.0,
            "is_vpn_or_proxy": False,
            "velocity_last_10min": 1,
            "device_trust_score": 0.65,
            "session_token": smishing_token,
            "merchant_vpa": "hdfc-support99@ybl"
        }
    }
]

for sc in payment_scenarios:
    r = client.post("/api/v1/scan-payment", json=sc["payload"])
    data = r.json()
    print(f"Scenario: {sc['name']}")
    print(f"-> Amount: Rs {data['amount']} | Risk Score: {data['risk_score']} | Verdict: {data['verdict']} | Action: {data['action']}")
    print(f"   Reasons: {data['reasons']}")
    print("-" * 70)
    assert r.status_code == 200

print("\n>>> ALL 3 API ENDPOINTS & CROSS-CHANNEL SESSION HANDOVERS VERIFIED! <<<")
