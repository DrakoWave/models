# config.py
"""
Configuration settings and centralized thresholds for UV- Ultra Vigilance backend.
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
DOMAIN_MODEL_PATH = MODELS_DIR / "domain_xgb.pkl"
SMS_MODEL_PATH = MODELS_DIR / "sms_clf.pkl"

# Verdict Classification Thresholds (Confidence between 0.0 and 1.0)
FRAUD_THRESHOLD = 0.70
SUSPICIOUS_THRESHOLD = 0.40

# Network & External Query Timeouts
WHOIS_TIMEOUT = 3.0
SHORTENED_URL_TIMEOUT = 3.0

# Domain Recency Threshold (days)
NEW_DOMAIN_DAYS_THRESHOLD = 14

# Heuristic Booster Weights
NEW_DOMAIN_BOOST = 0.45
SHARED_HOSTING_IMPERSONATION_BOOST = 0.50
RAW_PHONE_SENDER_BOOST = 0.15
KNOWN_SHORTENER_BOOST = 0.25
URGENCY_FINANCIAL_BOOST = 0.35
