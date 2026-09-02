# tests/test_sms.py
import sys
from pathlib import Path
import joblib

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.sms_engine import compute_sms_risk_score

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

sms_bundle = joblib.load(BASE_DIR / "models" / "sms_clf.pkl")
domain_model = joblib.load(BASE_DIR / "models" / "domain_xgb.pkl")

test_cases = [
    # 1. Benign Personal
    {"sender": "+919876543210", "text": "Hey, let's meet tomorrow at 4 PM near the cafeteria."},
    # 2. Legitimate Bank Transaction
    {"sender": "VM-HDFCBK", "text": "Dear Customer, INR 4,500.00 debited from A/C XX1290 on 02-Sep. Info: UPI/AMAZON. Bal: INR 35,400.00."},
    # 3. Legitimate Bank OTP
    {"sender": "AD-SBINB", "text": "582910 is the OTP for SBI NetBanking login. Valid for 5 mins. Do not share OTP with anyone."},
    # 4. Legitimate Bank with Allowlisted URL
    {"sender": "VK-HDFCBK", "text": "Dear Customer, check your latest credit card e-statement at https://netbanking.hdfcbank.com/netbanking/"},
    # 5. Smishing: KYC Expiry with Phishing URL
    {"sender": "CP-HDFCAC", "text": "Dear customer, your HDFC NetBanking is blocked due to incomplete PAN KYC. Update immediately: http://hdfc-kyc-verification.top/auth"},
    # 6. Smishing: Electricity Cutoff
    {"sender": "VK-POWERC", "text": "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Pay immediately: http://bijli-bill-quickpay.xyz"},
    # 7. Smishing: Fake APK Lure
    {"sender": "DM-PAYTMK", "text": "Paytm KYC Reward: Rs 3,000 waiting. Download KYC helper APK to claim: http://paytm-security-update.club/paytm.apk"},
    # 8. Smishing: Traffic Challan
    {"sender": "BP-ECHLN", "text": "Notice: Pending traffic challan of Rs 1000 against your vehicle. Clear court fine at http://echallan-parivahan-pay.site"}
]

print("\n" + "="*120)
print(f"{'Sender':<12} | {'Risk':<5} | {'Verdict':<12} | {'Embedded URLs / Reasons'}")
print("="*120)

for case in test_cases:
    res = compute_sms_risk_score(case["text"], sms_bundle, domain_model, sender=case["sender"])
    sender = res["sender"]
    risk = f"{res['risk_score']:.2f}"
    verdict = "[SMISHING]" if res["is_threat"] else "[SAFE]"
    reasons_str = "; ".join(res["reasons"])
    if res["embedded_urls"]:
        urls_info = ", ".join([f"{u['url']} (Risk: {u['risk_score']})" for u in res["embedded_urls"]])
        reasons_str = f"URLs: [{urls_info}] | {reasons_str}"
    print(f"{sender:<12} | {risk:<5} | {verdict:<12} | {reasons_str}")
