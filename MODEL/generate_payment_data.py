# generate_payment_data.py
"""
Generates 100,000 realistic payment transactions for training the enterprise
Payment Gateway Fraud Interception Engine:
- Legitimate transactions (~80,000)
- Sophisticated fraud patterns (~20,000):
  * SMS-lure victim checkouts (chained attack)
  * Sub-second bot credential stuffing & micro-auth bursts
  * Midnight high-value drain transactions
  * Anonymized VPN/proxy takeovers & velocity spikes
Saves to: datasets/payment_transactions.csv
"""
import os
import random
import pandas as pd
import numpy as np

os.makedirs("datasets", exist_ok=True)
output_path = "datasets/payment_transactions.csv"

TOTAL_SAMPLES = 100000
FRAUD_RATIO = 0.20
NUM_FRAUD = int(TOTAL_SAMPLES * FRAUD_RATIO)  # 20,000
NUM_LEGIT = TOTAL_SAMPLES - NUM_FRAUD         # 80,000

print(f"Generating {TOTAL_SAMPLES} realistic payment transactions ({NUM_LEGIT} Legit, {NUM_FRAUD} Fraud)...")

data = []

# 1. Generate 80,000 Legitimate Transactions
hour_weights = [
    0.01, 0.01, 0.01, 0.01, 0.01, 0.02, 0.03, 0.05, 0.07, 0.08,
    0.08, 0.08, 0.07, 0.06, 0.06, 0.07, 0.08, 0.08, 0.06, 0.05,
    0.04, 0.03, 0.02, 0.01
]
hour_probs = np.array(hour_weights) / sum(hour_weights)

for _ in range(NUM_LEGIT):
    # Log-normal distribution for typical retail/UPI amounts (Rs 50 - Rs 35,000)
    amount = round(float(np.random.lognormal(mean=7.2, sigma=1.1) + 20), 2)
    amount = min(amount, 65000.00)
    
    # Peak daytime hours
    tx_hour = int(np.random.choice(range(24), p=hour_probs))
    
    # Human form fill duration (typically 4.5s to 45.0s)
    form_fill_duration = round(float(np.random.normal(loc=15.0, scale=5.5)), 2)
    form_fill_duration = max(3.0, min(form_fill_duration, 75.0))
    
    is_vpn_or_proxy = 1 if random.random() < 0.03 else 0
    velocity_last_10min = int(np.random.choice([1, 2, 3], p=[0.90, 0.08, 0.02]))
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

# 2. Generate 20,000 Fraudulent Transactions
for _ in range(NUM_FRAUD):
    fraud_pattern = random.choice(["sms_lure_drain", "bot_autofill_burst", "midnight_drain", "vpn_proxy_takeover", "card_testing"])
    
    if fraud_pattern == "sms_lure_drain":
        # Victim tricked by KYC/PAN SMS link -> high-value unauthorized checkout
        amount = round(float(random.uniform(3500.0, 49999.0)), 2)
        tx_hour = random.randint(0, 23)
        form_fill_duration = round(float(random.uniform(4.0, 20.0)), 2)
        is_vpn_or_proxy = 1 if random.random() < 0.35 else 0
        velocity_last_10min = random.choice([1, 2, 3, 4])
        device_trust_score = round(float(random.uniform(0.15, 0.65)), 2)
        origin_from_sms_lure = 1
        
    elif fraud_pattern == "bot_autofill_burst":
        # Sub-second automated bot form submission
        amount = round(float(random.uniform(10.0, 499.0)), 2)
        tx_hour = random.randint(0, 23)
        form_fill_duration = round(float(random.uniform(0.08, 1.45)), 2)  # < 1.5s
        is_vpn_or_proxy = 1 if random.random() < 0.85 else 0
        velocity_last_10min = random.randint(4, 20)  # High rapid velocity
        device_trust_score = round(float(random.uniform(0.05, 0.35)), 2)
        origin_from_sms_lure = 0
        
    elif fraud_pattern == "midnight_drain":
        # Unusual late-night high-value drain
        amount = round(float(random.uniform(18000.0, 95000.0)), 2)
        tx_hour = random.choice([0, 1, 2, 3, 4, 5])
        form_fill_duration = round(float(random.uniform(1.0, 6.0)), 2)
        is_vpn_or_proxy = 1 if random.random() < 0.70 else 0
        velocity_last_10min = random.choice([2, 3, 5, 8])
        device_trust_score = round(float(random.uniform(0.10, 0.40)), 2)
        origin_from_sms_lure = 1 if random.random() < 0.50 else 0
        
    elif fraud_pattern == "card_testing":
        # Rapid micro-transactions across stolen cards
        amount = round(float(random.uniform(1.0, 99.0)), 2)
        tx_hour = random.randint(0, 23)
        form_fill_duration = round(float(random.uniform(0.2, 1.8)), 2)
        is_vpn_or_proxy = 1 if random.random() < 0.90 else 0
        velocity_last_10min = random.randint(6, 25)
        device_trust_score = round(float(random.uniform(0.02, 0.25)), 2)
        origin_from_sms_lure = 0
        
    else:  # vpn_proxy_takeover
        amount = round(float(random.uniform(4000.0, 42000.0)), 2)
        tx_hour = random.randint(0, 23)
        form_fill_duration = round(float(random.uniform(0.8, 4.0)), 2)
        is_vpn_or_proxy = 1
        velocity_last_10min = random.randint(3, 10)
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
df = df.sample(frac=1, random_state=42).reset_index(drop=True)
df.to_csv(output_path, index=False)

print(f"\nSUCCESS! 100,000 Transactions Dataset Created: {output_path}")
print(f"Total Rows: {len(df)}")
print("Class Breakdown:")
print(df["is_fraud"].value_counts())
