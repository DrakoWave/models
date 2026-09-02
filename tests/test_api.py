# tests/test_api.py
import json
import sys
from pathlib import Path
from fastapi.testclient import TestClient

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from api.server import app

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

client = TestClient(app)

print("="*90)
print("1. Testing /health Endpoint")
print("="*90)
resp = client.get("/health")
print(f"Status: {resp.status_code}")
print(json.dumps(resp.json(), indent=2))
assert resp.status_code == 200

print("\n" + "="*90)
print("2. Testing /api/scan/domain (Person B - Chrome Extension Contract)")
print("="*90)
domains = [
    "https://netbanking.hdfcbank.com/netbanking/",
    "http://hdfc-kyc-verification.top/auth",
    "https://secure-login-sbi-update.xyz/verify"
]

for url in domains:
    resp = client.post("/api/scan/domain", json={"url": url})
    data = resp.json()
    print(f"URL: {url}")
    print(f"-> Risk: {data['risk_score']} | Verdict: {data['verdict']} | Action: {data['action']}")
    print(f"   Reasons: {data['reasons']}")
    print("-" * 70)
    assert resp.status_code == 200

print("\n" + "="*90)
print("3. Testing /api/scan/sms (Person C - Android App Contract)")
print("="*90)
sms_samples = [
    {
        "sender": "VM-HDFCBK",
        "message": "Dear Customer, INR 4,500.00 debited from A/C XX1290 on 02-Sep. Info: UPI/AMAZON."
    },
    {
        "sender": "CP-HDFCAC",
        "message": "Dear customer, your HDFC NetBanking is blocked due to incomplete PAN KYC. Update immediately: http://hdfc-kyc-verification.top/auth"
    }
]

smishing_token = None
for sms in sms_samples:
    resp = client.post("/api/scan/sms", json=sms)
    data = resp.json()
    print(f"Sender: {data['sender']}")
    print(f"-> Risk: {data['risk_score']} | Verdict: {data['verdict']} | Token: {data.get('session_token')}")
    print(f"   Reasons: {data['reasons']}")
    print("-" * 70)
    assert resp.status_code == 200
    if data.get("session_token"):
        smishing_token = data["session_token"]

print("\n" + "="*90)
print("4. Testing /api/scan/payment (Person B - Gateway Interception Hook Contract)")
print("="*90)
payment_tests = [
    {
        "checkout_url": "https://amazon.in/checkout/pay",
        "merchant_vpa": "amazonpay@hdfcbank",
        "amount": 1499.00,
        "session_token": None
    },
    {
        "checkout_url": "http://hdfc-kyc-verification.top/pay",
        "merchant_vpa": "hdfc-support99@ybl",
        "amount": 5000.00,
        "session_token": smishing_token
    }
]

for p in payment_tests:
    resp = client.post("/api/scan/payment", json=p)
    data = resp.json()
    print(f"Checkout: {data['checkout_url']} | VPA: {data['merchant_vpa']} | Amount: Rs {data['amount']}")
    print(f"-> Risk: {data['risk_score']} | Verdict: {data['verdict']} | Action: {data['action']}")
    print(f"   Reasons: {data['reasons']}")
    print("-" * 70)
    assert resp.status_code == 200

print("\n>>> ALL API CONTRACT TESTS PASSED PERFECTLY! <<<")
