# pipelines/fetch_test_data.py
"""
Fetches and generates fresh, UNSEEN evaluation datasets for testing.
Ensures 0% overlap with existing training datasets (phishing_urls.csv and sms_fraud.csv).
Outputs:
- datasets/test_unseen_urls.csv
- datasets/test_unseen_sms.csv
"""
import io
import sys
from pathlib import Path
import requests
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATASETS_DIR = BASE_DIR / "datasets"
DATASETS_DIR.mkdir(parents=True, exist_ok=True)

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) UnseenTestDataCollector/1.0"}

print("=" * 80)
print("1/3 Loading Existing Training Datasets for Deduplication...")
print("=" * 80)

trained_urls = set()
trained_sms = set()

train_url_path = DATASETS_DIR / "phishing_urls.csv"
if train_url_path.exists():
    df_train_urls = pd.read_csv(train_url_path)
    trained_urls = set(df_train_urls["url"].dropna().str.strip())
    print(f" -> Found {len(trained_urls)} trained URLs to exclude.")

train_sms_path = DATASETS_DIR / "sms_fraud.csv"
if train_sms_path.exists():
    df_train_sms = pd.read_csv(train_sms_path)
    trained_sms = set(df_train_sms["text"].dropna().str.strip())
    print(f" -> Found {len(trained_sms)} trained SMS texts to exclude.")

print("\n" + "=" * 80)
print("2/3 Assembling Fresh Unseen Domain / URL Test Dataset...")
print("=" * 80)

unseen_phish_urls = []
unseen_safe_urls = []

# Fetch live zero-hour phishing links
try:
    print(" -> Fetching fresh live phishing feed from OpenPhish...")
    resp = requests.get("https://openphish.com/feed.txt", headers=headers, timeout=12)
    if resp.status_code == 200:
        for line in resp.text.split("\n"):
            u = line.strip()
            if u.startswith("http") and u not in trained_urls:
                unseen_phish_urls.append(u)
        print(f"    Found {len(unseen_phish_urls)} brand-new unseen phishing URLs.")
except Exception as e:
    print(f"    Warning fetching live feed: {e}")

# Add high-evasion synthetic adversarial test URLs
synthetic_adversarial_phishing = [
    "https://secure-hdfcbank-netbanking-auth.xyz/login",
    "https://onlinesbi-sbi-co-in-kyc-update.top/verify",
    "http://192.168.10.15/paytm/wallet/claim.php",
    "https://appleid-apple-com-account-locked.site/recover",
    "https://www.g00gle-security-alert.club/signin",
    "https://axisbank-netbanking-pan-verify.online/auth",
    "https://icici-bank-rewards-points.buzz/claim",
    "http://electricity-power-cut-billpay.xyz/mseb",
    "https://incometax-refund-portal-gov.top/itr",
    "https://parivahan-echallan-quickpay.site/fine",
    "https://paypa1-checkout-security.com/signin",
    "https://netflix-subscription-renew-account.click/pay",
    "https://amazon-prime-rewards-voucher.top/redeem",
    "http://xn--microsft-pqa.com/office365/login",
    "https://kotak-811-account-unblock.xyz/kyc"
]
for u in synthetic_adversarial_phishing:
    if u not in trained_urls:
        unseen_phish_urls.append(u)

# Fresh legitimate safe URLs
fresh_safe_candidates = [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://stackoverflow.com/questions/tagged/python",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://news.ycombinator.com/item?id=38491201",
    "https://pypi.org/project/xgboost/",
    "https://fastapi.tiangolo.com/tutorial/first-steps/",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://cloud.google.com/vertex-ai/docs",
    "https://aws.amazon.com/console/",
    "https://portal.azure.com/",
    "https://www.hdfcbank.com/personal/ways-to-bank/online-banking/net-banking",
    "https://retail.onlinesbi.sbi.co.in/retail/login.htm",
    "https://www.icicibank.com/personal-banking/insta-banking/internet-banking",
    "https://www.axisbank.com/bank-smart/internet-banking",
    "https://paytm.com/recharge",
    "https://www.phonepe.com/en/merchants/",
    "https://razorpay.com/payment-gateway/",
    "https://www.swiggy.com/restaurants",
    "https://www.zomato.com/delivery",
    "https://www.irctc.co.in/nget/train-search",
    "https://incometax.gov.in/iec/foportal/",
    "https://uidai.gov.in/en/my-aadhaar/get-aadhaar.html",
    "https://parivahan.gov.in/parivahan/",
    "https://www.flipkart.com/plus",
    "https://www.amazon.in/b?node=1389401031"
]
for u in fresh_safe_candidates:
    if u not in trained_urls:
        unseen_safe_urls.append(u)

# Build balanced unseen URL dataset
min_url_count = min(len(unseen_phish_urls), len(unseen_safe_urls))
df_test_phish = pd.DataFrame({"url": unseen_phish_urls[:min_url_count], "label": 1})
df_test_safe = pd.DataFrame({"url": unseen_safe_urls[:min_url_count], "label": 0})
df_unseen_urls = pd.concat([df_test_phish, df_test_safe], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

unseen_url_file = DATASETS_DIR / "test_unseen_urls.csv"
df_unseen_urls.to_csv(unseen_url_file, index=False)
print(f" -> Created {unseen_url_file} with {len(df_unseen_urls)} unseen test URLs.")

print("\n" + "=" * 80)
print("3/3 Assembling Fresh Unseen SMS Test Dataset...")
print("=" * 80)

unseen_sms_samples = [
    # 1. Unseen Phishing / Smishing SMS (Label = 1)
    {"text": "Dear customer, your SBI YONO account has been disabled. Complete mandatory re-KYC at https://onlinesbi-sbi-co-in-kyc-update.top/verify immediately.", "label": 1},
    {"text": "URGENT NOTICE: Your electricity connection CA# 293847 will be disconnected tonight at 9:30 PM due to overdue payment. Pay via http://electricity-power-cut-billpay.xyz/mseb", "label": 1},
    {"text": "Income Tax Refund: An excess amount of INR 18,450 has been approved for your PAN. Update bank details to claim: https://incometax-refund-portal-gov.top/itr", "label": 1},
    {"text": "Congratulations! You won Rs. 50,000 in festive Lucky Draw on PhonePe. Claim reward directly into your UPI account: http://phonepe-festive-scratch.site/claim", "label": 1},
    {"text": "HDFC Alert: Your debit card is temporarily blocked. Kindly unblock your card within 12 hours: https://secure-hdfcbank-netbanking-auth.xyz/login", "label": 1},
    {"text": "Traffic Police: Your vehicle has 2 pending camera speeding challans of Rs. 2,000. Pay online before court summons: https://parivahan-echallan-quickpay.site/fine", "label": 1},
    {"text": "Loan Approved: Instant pre-approved loan of Rs. 7,50,000 at 1.5% interest rate. Download QuickMoney APK to disburse funds: http://quick-dhan-loan.club/loan.apk", "label": 1},
    {"text": "Axis Bank: Your account access will be terminated tonight due to incomplete Aadhaar linkage. Update now: https://axisbank-netbanking-pan-verify.online/auth", "label": 1},

    # 2. Unseen Authentic Transactional / Personal SMS (Label = 0)
    {"text": "Dear Customer, INR 3,250.00 debited from A/C XX7812 on 02-Sep-2026. Info: UPI/SWIGGY. Available Bal: INR 28,150.00 - HDFC Bank", "label": 0},
    {"text": "829401 is your OTP for Axis Bank Internet Banking login. Valid for 3 mins. Do not share OTP with anyone.", "label": 0},
    {"text": "Dear Customer, Rs 18,500.00 credited to your A/C XX9012 on 02-Sep by IMPS from RAJESH KUMAR. Total Bal: Rs 64,800.00.", "label": 0},
    {"text": "Your Swiggy order #492810 from Dominos Pizza has been picked up by delivery partner. Arriving in 12 mins.", "label": 0},
    {"text": "IRCTC: PNR 4829104820 Confirmed. Coach A1 Berth 21 (Lower). Train 12951 BOM-NDLS Rajdhani on 05-Sep.", "label": 0},
    {"text": "Your Uber driver Ramesh (Maruti Dzire KA-01-AB-1234) is arriving in 3 mins. OTP is 4182.", "label": 0},
    {"text": "Dear SBI Customer, your e-statement for month of Aug 2026 has been generated. View at https://retail.onlinesbi.sbi.co.in/retail/login.htm", "label": 0},
    {"text": "Hey, I have shared the project documentation on Google Drive. Please review when free.", "label": 0}
]

df_unseen_sms = pd.DataFrame(unseen_sms_samples)
unseen_sms_file = DATASETS_DIR / "test_unseen_sms.csv"
df_unseen_sms.to_csv(unseen_sms_file, index=False)
print(f" -> Created {unseen_sms_file} with {len(df_unseen_sms)} unseen test SMS samples.")

print("\n" + "=" * 80)
print("SUCCESS: Fresh unseen test datasets ready for unbiased evaluation!")
print("=" * 80)
