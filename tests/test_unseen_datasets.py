# tests/test_unseen_datasets.py
"""
Evaluates trained models against completely UNSEEN test data from:
- datasets/test_unseen_urls.csv
- datasets/test_unseen_sms.csv
"""
import sys
from pathlib import Path
import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.domain_engine import compute_risk_score
from core.sms_engine import compute_sms_risk_score

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

domain_model = joblib.load(BASE_DIR / "models" / "domain_xgb.pkl")
sms_bundle = joblib.load(BASE_DIR / "models" / "sms_clf.pkl")

print("=" * 100)
print("1. EVALUATION ON UNSEEN DOMAIN / URL TEST DATASET (datasets/test_unseen_urls.csv)")
print("=" * 100)

df_urls = pd.read_csv(BASE_DIR / "datasets" / "test_unseen_urls.csv")
y_true_urls = df_urls["label"].tolist()
y_pred_urls = []
scores_urls = []
reasons_urls = []

for u in df_urls["url"]:
    score, reasons = compute_risk_score(u, domain_model)
    scores_urls.append(score)
    is_phish = 1 if score >= 0.50 else 0
    y_pred_urls.append(is_phish)
    reasons_urls.append(", ".join(reasons) if reasons else "None")

print(f"Total Unseen URLs Tested: {len(df_urls)}")
print(f"Accuracy: {accuracy_score(y_true_urls, y_pred_urls) * 100:.2f}%\n")
print(classification_report(y_true_urls, y_pred_urls, target_names=["Safe (0)", "Phishing (1)"], digits=4))
print("Confusion Matrix:\n", confusion_matrix(y_true_urls, y_pred_urls))

print("\nSample Predictions on Unseen URLs:")
print(f"{'URL':<50} | {'Score':<6} | {'Pred':<8} | {'True':<6} | {'Reasons'}")
print("-" * 115)
for i in range(min(10, len(df_urls))):
    u = df_urls["url"].iloc[i]
    pred_str = "PHISH" if y_pred_urls[i] == 1 else "SAFE"
    true_str = "PHISH" if y_true_urls[i] == 1 else "SAFE"
    print(f"{u[:48]:<50} | {scores_urls[i]:.2f}  | {pred_str:<8} | {true_str:<6} | {reasons_urls[i][:40]}")

print("\n" + "=" * 100)
print("2. EVALUATION ON UNSEEN SMS TEST DATASET (datasets/test_unseen_sms.csv)")
print("=" * 100)

df_sms = pd.read_csv(BASE_DIR / "datasets" / "test_unseen_sms.csv")
y_true_sms = df_sms["label"].tolist()
y_pred_sms = []
scores_sms = []
reasons_sms = []

for text in df_sms["text"]:
    res = compute_sms_risk_score(text, sms_bundle, domain_model)
    scores_sms.append(res["risk_score"])
    is_smish = 1 if res["is_threat"] else 0
    y_pred_sms.append(is_smish)
    reasons_sms.append("; ".join(res["reasons"]) if res["reasons"] else "None")

print(f"Total Unseen SMS Samples Tested: {len(df_sms)}")
print(f"Accuracy: {accuracy_score(y_true_sms, y_pred_sms) * 100:.2f}%\n")
print(classification_report(y_true_sms, y_pred_sms, target_names=["Ham/Legit (0)", "Smishing (1)"], digits=4))
print("Confusion Matrix:\n", confusion_matrix(y_true_sms, y_pred_sms))

print("\nSample Predictions on Unseen SMS Messages:")
print(f"{'SMS Snippet':<50} | {'Score':<6} | {'Pred':<8} | {'True':<6} | {'Reasons'}")
print("-" * 115)
for i in range(len(df_sms)):
    t = df_sms["text"].iloc[i]
    pred_str = "SMISH" if y_pred_sms[i] == 1 else "SAFE"
    true_str = "SMISH" if y_true_sms[i] == 1 else "SAFE"
    print(f"{t[:48]:<50} | {scores_sms[i]:.2f}  | {pred_str:<8} | {true_str:<6} | {reasons_sms[i][:40]}")
