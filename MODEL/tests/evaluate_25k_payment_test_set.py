# tests/evaluate_25k_payment_test_set.py
"""
Evaluates the trained payment model on the 25,000 unseen test dataset:
datasets/payment_test_25k.csv

STRICT: NO MODEL TRAINING OR RETRAINING OCCURS IN THIS SCRIPT.
"""
import sys
import time
from pathlib import Path
import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from payment_engine import compute_payment_risk

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

model_path = BASE_DIR / "models" / "payment_risk.pkl"
test_csv_path = BASE_DIR / "datasets" / "payment_test_25k.csv"

print("=" * 90)
print(f"Loading 25,000 Payment Test Dataset from {test_csv_path}...")
print("=" * 90)

df_test = pd.read_csv(test_csv_path)
model = joblib.load(model_path)

print(f"Total Transactions: {len(df_test)}")
print("Class Distribution:\n", df_test["is_fraud"].value_counts().to_dict())

print("\nRunning Pure Inference Across 25,000 Transactions...")
t0 = time.perf_counter()

y_true = df_test["is_fraud"].tolist()
y_pred = []
scores = []

for _, row in df_test.iterrows():
    payload = row.to_dict()
    score, _ = compute_payment_risk(payload, model)
    scores.append(score)
    y_pred.append(1 if score >= 0.50 else 0)

total_time = time.perf_counter() - t0
avg_ms = (total_time / len(df_test)) * 1000

print(f" -> Evaluated 25,000 transactions in {total_time:.2f}s ({avg_ms:.3f} ms per transaction)")

print("\n" + "=" * 90)
print("25,000 TEST PAYMENT DATASET BENCHMARK REPORT")
print("=" * 90)
print(f"Overall Accuracy: {accuracy_score(y_true, y_pred) * 100:.2f}%\n")
print(classification_report(y_true, y_pred, target_names=["Legitimate (0)", "Fraudulent (1)"], digits=4))
roc_auc = roc_auc_score(y_true, scores)
print(f"ROC-AUC Score: {roc_auc:.4f}")
print("\nConfusion Matrix:\n", confusion_matrix(y_true, y_pred))
