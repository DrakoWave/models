# pipelines/train_sms.py
import os
import io
import sys
from pathlib import Path
import requests
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

MODELS_DIR = BASE_DIR / "models"
DATASETS_DIR = BASE_DIR / "datasets"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
DATASETS_DIR.mkdir(parents=True, exist_ok=True)

print("1/4 Loading base SMS dataset...")
uci_sms_url = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
try:
    resp = requests.get(uci_sms_url, timeout=10)
    df_base = pd.read_csv(io.StringIO(resp.text), sep="\t", header=None, names=["label_str", "text"])
    df_base["label"] = df_base["label_str"].map({"ham": 0, "spam": 1})
    df_base = df_base[["text", "label"]].dropna()
    print(f" -> Loaded {len(df_base)} samples from baseline SMS dataset.")
except Exception as e:
    print(f"Warning fetching UCI dataset ({e}). Generating standard fallback baseline...")
    df_base = pd.DataFrame([
        ("Hey are we meeting today for coffee?", 0),
        ("Your OTP for Uber login is 482910. Do not share with anyone.", 0),
        ("Your Swiggy order has been delivered. Enjoy your meal!", 0),
        ("Salary of INR 65,000 credited to A/C XX4019 on 01-Sep.", 0),
        ("Win a free brand new iPhone 15 by texting WIN to 88022 now!", 1),
        ("URGENT: Claim your lottery prize of 1000000 pounds immediately!", 1),
    ], columns=["text", "label"])

print("2/4 Augmenting with targeted Indian Smishing & Transactional lures...")
augmented_samples = [
    # Smishing - Bank KYC / Account Blocked (label=1)
    ("Dear customer, your HDFC bank account has been suspended due to pending PAN KYC. Update immediately at http://hdfc-kyc-verification.top/auth", 1),
    ("SBI Alert: Your NetBanking access is blocked. Complete your mandatory KYC document submission at https://secure-login-sbi-update.xyz/verify", 1),
    ("ICICI Bank: Your debit card is deactivated due to KYC non-compliance. Click http://icici-card-kyc-renew.online to unblock within 24 hours.", 1),
    ("AXIS BANK: Dear user, update your PAN card details to avoid account deactivation: http://axis-pan-update-portal.xyz/login", 1),
    ("Punjab National Bank: Your A/C will be suspended today. Click http://pnb-kyc-update-portal.top to verify Aadhar card.", 1),
    ("Bank of Baroda: Important! Update your mobile number and PAN to keep account active: http://bob-kyc-update.xyz", 1),
    
    # Smishing - Electricity / Utility Disconnection (label=1)
    ("Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM from the main sub-station due to unpaid bill. Immediately contact our electricity officer at 9812345678 or pay via http://bijli-bill-quickpay.xyz", 1),
    ("URGENT: Mahavitaran Electricity bill overdue. Power cutoff order issued. Call bill supervisor immediately or download helper APK: http://mseb-quick-bill-support.top/app.apk", 1),
    ("BSES Alert: Disconnection notice generated for CA 102938472. Clear bill immediately to avoid blackout: http://bses-quickpay-online.site", 1),
    
    # Smishing - Fake APK / UPI / Lottery / Cashback (label=1)
    ("Congratulations! You have received a cashback reward of Rs 2,500 on PhonePe. Claim directly to your bank account: http://phonepe-reward-scratch.site/claim", 1),
    ("Paytm KYC Reward: Rs 3,000 credit waiting in your wallet. Download Paytm KYC Assistant APK to claim: http://paytm-security-update.club/paytm.apk", 1),
    ("Dear User, your instant personal loan of Rs 5,00,000 is approved with 0% interest. Download loan app now: http://instant-dhan-loan-app.buzz/get", 1),
    ("Challan Notice: You have 1 pending traffic violation e-challan of Rs 1,000. Pay before court action at http://echallan-parivahan-pay.site", 1),
    ("Earn Rs 5000 daily by working part-time from home on YouTube likes. Register here: http://daily-parttime-earn.club", 1),
    ("Your package cannot be delivered due to wrong address. Update address within 12 hours: http://indiapost-parcel-update.top", 1),

    # Authentic / Safe - Legitimate Indian Banking & Service SMS (label=0)
    ("Dear Customer, INR 4,500.00 debited from A/C XX1290 on 02-Sep. Info: UPI/AMAZON. Bal: INR 35,400.00.", 0),
    ("Dear Customer, Rs 1,250.00 debited from A/C **8921 on 02-Sep-2026 via UPI to ZOMATO. Avail Bal: Rs 42,100.00 - HDFC Bank", 0),
    ("Dear Customer, Rs 50,000.00 credited to your A/C XX3412 on 01-Sep by NEFT from INFOSYS LTD. Total Bal: Rs 1,45,200.00.", 0),
    ("Rs 250.00 debited from your Paytm Payments Bank A/C XX9012 for Swiggy order. Updated Bal: Rs 3,420.00.", 0),
    ("Dear SBI User, A/C 9812 debited by Rs 1500.00 on 02Sep26 transfer to GPay. Ref No 624519283741.", 0),
    ("Your ICICI Bank Credit Card ending 4012 was charged Rs 2,199 at NETFLIX on 02-Sep-2026.", 0),
    ("582910 is the OTP for SBI NetBanking login. Valid for 5 mins. Do not share OTP with anyone.", 0),
    ("492019 is your One Time Password (OTP) for HDFC Bank card verification at Amazon. OTP valid for 3 minutes.", 0),
    ("638102 is your login OTP for ICICI iMobile app. NEVER share your OTP, password or PIN with anyone.", 0),
    ("Your OTP for Uber ride confirmation is 7192. Share with driver to start trip.", 0),
    ("Dear Customer, check your latest credit card e-statement at https://netbanking.hdfcbank.com/netbanking/", 0),
    ("Dear Customer, your monthly bank statement for Aug 2026 has been sent to your registered email ID - HDFC Bank", 0),
    ("Dear Customer, your electricity bill of Rs 1,420 for Consumer ID 1092837 is due on 10-Sep. Pay via official app or bijli portal.", 0),
    ("Your Zomato delivery partner is arriving in 5 mins. Please collect your order.", 0),
    ("Your Swiggy order #9182374 from Burger King is confirmed and being prepared.", 0),
    ("Your Indigo flight 6E-204 from DEL to BOM is on time. Gate 4B. Web check-in available.", 0),
    ("IRCTC: PNR 2419827361 Confirmed. Coach B2 Seat 45 (Side Lower). Train 12952 NDLS-MMCT Rajdhani.", 0),
    ("Dear SBI Customer, your fixed deposit maturing on 15-Sep will be auto-renewed. Visit nearest branch for changes.", 0),
    ("Amazon: Your package with order #402-1928371 will be delivered today by 8 PM.", 0),
    ("Flipkart: Out for delivery! Wishmaster Rahul is arriving with your order.", 0),
    ("CRED: Your HDFC credit card bill of Rs 14,350 is due in 3 days. Pay now to earn coins.", 0),
    ("Zerodha: Order executed. Bought 10 shares of TATASTEEL at Rs 152.40.", 0),
    ("Hey are we meeting today for coffee?", 0),
    ("Can you please send me the presentation slides before 5 PM?", 0),
    ("Thanks for your help with the hackathon project!", 0)
]

df_augmented = pd.DataFrame(augmented_samples, columns=["text", "label"])
df_final = pd.concat([df_base, df_augmented], ignore_index=True).drop_duplicates(subset=["text"])

output_csv = DATASETS_DIR / "sms_fraud.csv"
df_final.to_csv(output_csv, index=False)
print(f" -> Total dataset: {len(df_final)} samples saved to {output_csv}")

print("3/4 Training TF-IDF + Logistic Regression Model...")
X_train, X_test, y_train, y_test = train_test_split(
    df_final["text"], df_final["label"], test_size=0.2, random_state=42, stratify=df_final["label"]
)

vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=10000, lowercase=True)
classifier = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)

X_train_vec = vectorizer.fit_transform(X_train)
classifier.fit(X_train_vec, y_train)

X_test_vec = vectorizer.transform(X_test)
y_pred = classifier.predict(X_test_vec)

print("\n--- SMS Smishing Classification Report ---")
print(classification_report(y_test, y_pred, target_names=["Ham/Legit", "Spam/Smishing"]))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

print("4/4 Saving model bundle to models/sms_clf.pkl...")
bundle = {
    "vectorizer": vectorizer,
    "classifier": classifier
}
model_path = MODELS_DIR / "sms_clf.pkl"
joblib.dump(bundle, model_path)
print(f"Success! Model bundle saved to: {model_path}")
