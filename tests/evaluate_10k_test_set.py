# tests/evaluate_10k_test_set.py
"""
Evaluates the existing trained models on the 10,000 test dataset:
datasets/domain_test_10k.csv

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

from core.domain_engine import compute_risk_score

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

domain_model = joblib.load(BASE_DIR / "models" / "domain_xgb.pkl")
test_csv_path = BASE_DIR / "datasets" / "domain_test_10k.csv"

print("=" * 90)
print(f"Loading 10,000 Test Dataset from {test_csv_path}...")
print("=" * 90)

df_test = pd.read_csv(test_csv_path)
print(f"Total Rows: {len(df_test)}")
print("Class Distribution:\n", df_test["label"].value_counts().to_dict())

print("\nRunning Inference Across 10,000 URLs...")
t0 = time.perf_counter()

y_true = df_test["label"].tolist()
y_pred = []
scores = []

for u in df_test["url"]:
    score, _ = compute_risk_score(u, domain_model)
    scores.append(score)
    y_pred.append(1 if score >= 0.50 else 0)

total_time = time.perf_counter() - t0
avg_ms = (total_time / len(df_test)) * 1000

print(f" -> Completed 10,000 URLs in {total_time:.2f}s ({avg_ms:.3f} ms per URL)")

print("\n" + "=" * 90)
print("10,000 TEST DATASET EVALUATION REPORT")
print("=" * 90)
print(f"Overall Accuracy: {accuracy_score(y_true, y_pred) * 100:.2f}%\n")
print(classification_report(y_true, y_pred, target_names=["Safe (0)", "Phishing (1)"], digits=4))
try:
    auc = roc_auc_score(y_true, scores)
    print(f"ROC-AUC Score: {auc:.4f}")
except Exception:
    pass
print("\nConfusion Matrix:\n", confusion_matrix(y_true, y_pred))
