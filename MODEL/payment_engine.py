# payment_engine.py
"""
Payment Gateway Fraud Interception Engine.
Computes real-time checkout risk based on transactional signals, behavioral heuristics,
and cross-channel SMS smishing attack chain correlation.
"""
from typing import Tuple, List, Dict, Any
import pandas as pd

FEATURE_COLUMNS = [
    "amount",
    "tx_hour",
    "form_fill_duration",
    "is_vpn_or_proxy",
    "velocity_last_10min",
    "device_trust_score",
    "origin_from_sms_lure"
]

def extract_payment_features(payload: Dict[str, Any]) -> pd.DataFrame:
    """
    Extracts normalized numeric features from an incoming payment checkout payload.
    """
    amount = float(payload.get("amount", 0.0))
    tx_hour = int(payload.get("tx_hour", 12))
    form_fill_duration = float(payload.get("form_fill_duration", 10.0))
    is_vpn_or_proxy = 1 if payload.get("is_vpn_or_proxy") in [True, 1, "true", "1"] else 0
    velocity_last_10min = int(payload.get("velocity_last_10min", 1))
    device_trust_score = float(payload.get("device_trust_score", 0.85))
    origin_from_sms_lure = 1 if payload.get("origin_from_sms_lure") in [True, 1, "true", "1"] else 0

    feature_dict = {
        "amount": [amount],
        "tx_hour": [tx_hour],
        "form_fill_duration": [form_fill_duration],
        "is_vpn_or_proxy": [is_vpn_or_proxy],
        "velocity_last_10min": [velocity_last_10min],
        "device_trust_score": [device_trust_score],
        "origin_from_sms_lure": [origin_from_sms_lure]
    }
    return pd.DataFrame(feature_dict)[FEATURE_COLUMNS]

def compute_payment_risk(payload: Dict[str, Any], model: Any) -> Tuple[float, List[str]]:
    """
    Hybrid scoring for payment checkout interception:
    Combines strict behavioral/threat heuristics with XGBoost classification probability.
    """
    reasons = []
    penalty = 0.0

    origin_from_sms = payload.get("origin_from_sms_lure") in [True, 1, "true", "1"]
    form_fill_duration = float(payload.get("form_fill_duration", 10.0))
    velocity = int(payload.get("velocity_last_10min", 1))
    is_vpn = payload.get("is_vpn_or_proxy") in [True, 1, "true", "1"]
    device_trust = float(payload.get("device_trust_score", 0.85))
    tx_hour = int(payload.get("tx_hour", 12))
    amount = float(payload.get("amount", 0.0))

    # Rule 1: Chained Smishing Origin (Immediate critical threat)
    if origin_from_sms:
        penalty += 0.85
        reasons.append("Chained Threat: User arrived via SMS Smishing Lure")

    # Rule 2: Sub-Second Bot Autofill
    if form_fill_duration < 1.5:
        penalty += 0.75
        reasons.append(f"Automated Bot Form Submission ({form_fill_duration:.2f}s duration)")

    # Rule 3: High-Velocity Rapid Burst
    if velocity >= 4:
        penalty += min(0.60, 0.35 + (velocity - 4) * 0.08)
        reasons.append(f"High-Velocity Rapid Transaction Burst ({velocity} tx in 10m)")

    # Rule 4: Anonymized Proxy / VPN on Untrusted Device
    if is_vpn:
        penalty += 0.30
        reasons.append("Anonymized Proxy / VPN Tunnel Detected")

    # Rule 5: Low Device Trust Score
    if device_trust < 0.40:
        penalty += 0.35
        reasons.append(f"Low Device Trust Reputation Score ({device_trust:.2f})")

    # Rule 6: Unusual Midnight High-Value Transaction
    if tx_hour in [0, 1, 2, 3, 4] and amount > 15000:
        penalty += 0.40
        reasons.append(f"High-Value Midnight Drain Alert (Rs {amount:.2f} at {tx_hour:02d}:00)")

    # ML Classifier Inference
    ml_prob = 0.0
    if model is not None:
        features_df = extract_payment_features(payload)
        ml_prob = float(model.predict_proba(features_df)[0][1])

    final_score = round(min(1.0, max(ml_prob, penalty)), 2)

    if final_score >= 0.50 and not reasons:
        reasons.append("Statistical Payment Risk Anomaly")

    return final_score, reasons
