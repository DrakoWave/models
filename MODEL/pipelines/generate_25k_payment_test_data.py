# pipelines/generate_25k_payment_test_data.py
"""
Generates 25,000 realistic payment transactions specifically for TESTING & EVALUATION.
Saves to: datasets/payment_test_25k.csv

STRICT ORDER: THIS SCRIPT DOES NOT TRAIN OR RETRAIN ANY MODEL.
"""
import os
import random
from pathlib import Path
import pandas as pd
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent
DATASETS_DIR = BASE_DIR / "datasets"
DATASETS_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_CSV = DATASETS_DIR / "payment_test_25k.csv"

TOTAL_SAMPLES = 25000
FRAUD_RATIO = 0.20
NUM_FRAUD = int(TOTAL_SAMPLES * FRAUD_RATIO)  # 5,000
NUM_LEGIT = TOTAL_SAMPLES - NUM_FRAUD         # 20,000

print(f"Generating {TOTAL_SAMPLES} realistic testing transactions ({NUM_LEGIT} Legit, {NUM_FRAUD} Fraud)...")

# Seed differently from training to guarantee distinct unseen distributions
np.random.seed(1337)
random.seed(1337)

data = []

# 1. Generate 20,000 Legitimate Testing Transactions
hour_weights = [
    0.01, 0.01, 0.01, 0.01, 0.01, 0.02, 0.03, 0.05, 0.07, 0.08,
    0.08, 0.08, 0.07, 0.06, 0.06, 0.07, 0.08, 0.08, 0.06, 0.05,
    0.04, 0.03, 0.02, 0.01
]
hour_probs = np.array(hour_weights) / sum(hour_weights)

for _ in range(NUM_LEGIT):
    amount = round(float(np.random.lognormal(mean=7.1, sigma=1.15) + 15), 2)
    amount = min(amount, 60000.00)
    tx_hour = int(np.random.choice(range(24), p=hour_probs))
    form_fill_duration = round(float(np.random.normal(loc=14.8, scale=5.2)), 2)
    form_fill_duration = max(3.0, min(form_fill_duration, 70.0))
    is_vpn_or_proxy = 1 if random.random() < 0.03 else 0
    velocity_last_10min = int(np.random.choice([1, 2, 3], p=[0.91, 0.07, 0.02]))
    device_trust_score = round(float(np.random.uniform(0.75, 1.00)), 2)
    origin_from_sms_lure = 0
    
    data.append({
        "amount": amount,
        "tx_hour": tx_hour,
        "form_fill_duration": form_fill_duration,
        "is_vpn_or_proxy": is_vpn_or_proxy,
        "velocity_last_10min": velocity_last_10min,
        "device_trust_score": device_trust_score,
        "origin_from_sms_lure": origin_from_sms_lure,
        "is_fraud": 0
    })

# 2. Generate 5,000 Fraudulent Testing Transactions
for _ in range(NUM_FRAUD):
    fraud_pattern = random.choice(["sms_lure_drain", "bot_autofill_burst", "midnight_drain", "vpn_proxy_takeover", "card_testing"])
    
    if fraud_pattern == "sms_lure_drain":
        amount = round(float(random.uniform(3000.0, 48000.0)), 2)
        tx_hour = random.randint(0, 23)
        form_fill_duration = round(float(random.uniform(3.5, 19.0)), 2)
        is_vpn_or_proxy = 1 if random.random() < 0.35 else 0
        velocity_last_10min = random.choice([1, 2, 3, 4])
        device_trust_score = round(float(random.uniform(0.15, 0.65)), 2)
        origin_from_sms_lure = 1
        
    elif fraud_pattern == "bot_autofill_burst":
        amount = round(float(random.uniform(10.0, 450.0)), 2)
        tx_hour = random.randint(0, 23)
        form_fill_duration = round(float(random.uniform(0.09, 1.45)), 2)
        is_vpn_or_proxy = 1 if random.random() < 0.85 else 0
        velocity_last_10min = random.randint(4, 20)
        device_trust_score = round(float(random.uniform(0.05, 0.35)), 2)
        origin_from_sms_lure = 0
        
    elif fraud_pattern == "midnight_drain":
        amount = round(float(random.uniform(17000.0, 92000.0)), 2)
        tx_hour = random.choice([0, 1, 2, 3, 4, 5])
        form_fill_duration = round(float(random.uniform(1.1, 5.8)), 2)
        is_vpn_or_proxy = 1 if random.random() < 0.70 else 0
        velocity_last_10min = random.choice([2, 3, 5, 8])
        device_trust_score = round(float(random.uniform(0.10, 0.40)), 2)
        origin_from_sms_lure = 1 if random.random() < 0.50 else 0
        
    elif fraud_pattern == "card_testing":
        amount = round(float(random.uniform(1.0, 89.0)), 2)
        tx_hour = random.randint(0, 23)
        form_fill_duration = round(float(random.uniform(0.2, 1.7)), 2)
        is_vpn_or_proxy = 1 if random.random() < 0.90 else 0
        velocity_last_10min = random.randint(6, 22)
        device_trust_score = round(float(random.uniform(0.02, 0.25)), 2)
        origin_from_sms_lure = 0
        
    else:  # vpn_proxy_takeover
        amount = round(float(random.uniform(4500.0, 40000.0)), 2)
        tx_hour = random.randint(0, 23)
        form_fill_duration = round(float(random.uniform(0.7, 3.8)), 2)
        is_vpn_or_proxy = 1
        velocity_last_10min = random.randint(3, 9)
        device_trust_score = round(float(random.uniform(0.05, 0.40)), 2)
        origin_from_sms_lure = 1 if random.random() < 0.40 else 0

    data.append({
        "amount": amount,
        "tx_hour": tx_hour,
        "form_fill_duration": form_fill_duration,
        "is_vpn_or_proxy": is_vpn_or_proxy,
        "velocity_last_10min": velocity_last_10min,
        "device_trust_score": device_trust_score,
        "origin_from_sms_lure": origin_from_sms_lure,
        "is_fraud": 1
    })

df = pd.DataFrame(data)
df = df.sample(frac=1, random_state=1337).reset_index(drop=True)
df.to_csv(OUTPUT_CSV, index=False)

print(f"\nSUCCESS! Created 25,000 Test Transactions Dataset: {OUTPUT_CSV}")
print(f"Total Rows: {len(df)}")
print("Class Breakdown:")
print(df["is_fraud"].value_counts())
