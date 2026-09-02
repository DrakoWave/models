# train_payment.py
"""
Trains XGBoost Payment Fraud Classifier with scale_pos_weight for class imbalance
and serializes model to models/payment_risk.pkl.
"""
import os
import joblib
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

os.makedirs("models", exist_ok=True)
csv_path = "datasets/payment_transactions.csv"

print("=" * 80)
print(f"Loading Payment Dataset from {csv_path}...")
print("=" * 80)
df = pd.read_csv(csv_path)

feature_cols = [
    "amount",
    "tx_hour",
    "form_fill_duration",
    "is_vpn_or_proxy",
    "velocity_last_10min",
    "device_trust_score",
    "origin_from_sms_lure"
]

X = df[feature_cols]
y = df["is_fraud"].astype(int)

print(f"Total Transactions: {len(df)}")
print(f"Class Breakdown: {df['is_fraud'].value_counts().to_dict()}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

# Calculate scale_pos_weight for 85/15 class imbalance
neg_count = (y_train == 0).sum()
pos_count = (y_train == 1).sum()
scale_weight = float(neg_count) / max(pos_count, 1)
print(f"Class imbalance weight (scale_pos_weight): {scale_weight:.3f}")

print("\nTraining XGBoost Payment Fraud Model...")
model = XGBClassifier(
    n_estimators=180,
    max_depth=5,
    learning_rate=0.08,
    scale_pos_weight=scale_weight,
    subsample=0.85,
    colsample_bytree=0.85,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

print("\n" + "=" * 80)
print("PAYMENT FRAUD CLASSIFICATION BENCHMARK REPORT")
print("=" * 80)
print(classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Fraudulent (1)"], digits=4))
roc_auc = roc_auc_score(y_test, y_proba)
print(f"ROC-AUC Score: {roc_auc:.4f}")
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

model_path = "models/payment_risk.pkl"
joblib.dump(model, model_path)
print(f"\nSuccess! Model saved to: {model_path}")
