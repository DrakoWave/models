# test_payment_model.py
"""
Test harness for Payment Gateway Fraud Interception Engine.
Verifies the 3 core evaluation scenarios.
"""
import sys
import joblib
from payment_engine import compute_payment_risk

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

print("Loading Payment Risk Model...")
model = joblib.load("models/payment_risk.pkl")

scenarios = [
    {
        "name": "1. Standard User Purchase",
        "payload": {
            "amount": 1499.00,
            "tx_hour": 14,
            "form_fill_duration": 18.5,
            "is_vpn_or_proxy": False,
            "velocity_last_10min": 1,
            "device_trust_score": 0.92,
            "origin_from_sms_lure": False
        },
        "expected_action": "APPROVE"
    },
    {
        "name": "2. Victim Arriving via SMS Smishing Link (Chained Attack)",
        "payload": {
            "amount": 12500.00,
            "tx_hour": 16,
            "form_fill_duration": 8.0,
            "is_vpn_or_proxy": False,
            "velocity_last_10min": 1,
            "device_trust_score": 0.60,
            "origin_from_sms_lure": True
        },
        "expected_action": "DECLINE"
    },
    {
        "name": "3. Bot Credential-Stuffing / Micro-Transaction Burst",
        "payload": {
            "amount": 49.00,
            "tx_hour": 3,
            "form_fill_duration": 0.45,
            "is_vpn_or_proxy": True,
            "velocity_last_10min": 9,
            "device_trust_score": 0.15,
            "origin_from_sms_lure": False
        },
        "expected_action": "DECLINE"
    }
]

print("\n" + "=" * 115)
print(f"{'Scenario':<42} | {'Risk Score':<10} | {'Decision':<10} | {'Status':<8} | {'Reasons'}")
print("=" * 115)

for sc in scenarios:
    score, reasons = compute_payment_risk(sc["payload"], model)
    decision = "DECLINE" if score >= 0.70 else ("REVIEW" if score >= 0.40 else "APPROVE")
    status = "PASS" if decision == sc["expected_action"] else "FAIL"
    reasons_str = "; ".join(reasons) if reasons else "None"
    print(f"{sc['name']:<42} | {score:<10.2f} | {decision:<10} | {status:<8} | {reasons_str}")

print("=" * 115)
