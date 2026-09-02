# pipelines/train_domain.py
import os
import sys
import time
from pathlib import Path
import joblib
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

# Add repository root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.domain_engine import extract_url_features

MODELS_DIR = BASE_DIR / "models"
DATASETS_DIR = BASE_DIR / "datasets"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

csv_path = DATASETS_DIR / "phishing_urls.csv"
print("=" * 80)
print(f"Loading Dataset from {csv_path}...")
print("=" * 80)
df = pd.read_csv(csv_path).dropna(subset=["url", "label"])
print(f"Total balanced dataset size: {len(df)} samples ({df['label'].value_counts().to_dict()})")

print("\nExtracting lexical, structural, and linguistic features...")
t0 = time.time()
feature_list = [extract_url_features(u) for u in df["url"]]
X = pd.DataFrame(feature_list)
y = df["label"].astype(int)
print(f" -> Feature matrix shape: {X.shape} extracted in {time.time() - t0:.2f}s")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"\nTraining High-Performance XGBoost Classifier on {len(X_train)} samples...")
model = XGBClassifier(
    n_estimators=250,
    max_depth=7,
    learning_rate=0.08,
    subsample=0.85,
    colsample_bytree=0.85,
    tree_method="hist",
    random_state=42,
    n_jobs=-1
)
t_train = time.time()
model.fit(X_train, y_train)
print(f" -> Model trained in {time.time() - t_train:.2f}s")

y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

print("\n" + "=" * 80)
print("ENTERPRISE DOMAIN CLASSIFICATION BENCHMARK REPORT")
print("=" * 80)
print(classification_report(y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"], digits=4))
roc_auc = roc_auc_score(y_test, y_proba)
print(f"ROC-AUC Score: {roc_auc:.4f}")
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

model_path = MODELS_DIR / "domain_xgb.pkl"
joblib.dump(model, model_path)
print(f"\nModel saved successfully to: {model_path}")
