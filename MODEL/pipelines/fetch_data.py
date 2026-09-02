# pipelines/fetch_data.py
import os
import io
from pathlib import Path
import requests
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATASETS_DIR = BASE_DIR / "datasets"
DATASETS_DIR.mkdir(parents=True, exist_ok=True)

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatIntelligenceEngine/2.0"}

print("=" * 80)
print("1/3 Fetching Live Multi-Source Phishing & Malicious URLs...")
print("=" * 80)

phish_urls = set()

# Source 1: OpenPhish Live Feed
try:
    print(" -> Fetching OpenPhish live feed...")
    resp = requests.get("https://openphish.com/feed.txt", headers=headers, timeout=12)
    if resp.status_code == 200:
        links = [line.strip() for line in resp.text.split("\n") if line.strip().startswith("http")]
        phish_urls.update(links)
        print(f"    Added {len(links)} URLs from OpenPhish.")
except Exception as e:
    print(f"    OpenPhish fetch warning: {e}")

# Source 2: URLhaus Live Database
try:
    print(" -> Fetching URLhaus live database...")
    urlhaus_resp = requests.get("https://urlhaus.abuse.ch/downloads/csv_online/", headers=headers, timeout=12)
    if urlhaus_resp.status_code == 200:
        count = 0
        for line in urlhaus_resp.text.split("\n"):
            if line and not line.startswith("#"):
                parts = line.split('","')
                if len(parts) > 2 and parts[2].startswith("http"):
                    clean_u = parts[2].replace('"', '').strip()
                    phish_urls.add(clean_u)
                    count += 1
        print(f"    Added {count} URLs from URLhaus.")
except Exception as e:
    print(f"    URLhaus fetch warning: {e}")

# Source 3: Active Curated Feeds
try:
    print(" -> Fetching Maltrail active phishing & malware domains feed...")
    m_resp = requests.get("https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt", headers=headers, timeout=12)
    if m_resp.status_code == 200:
        m_urls = ["http://" + line.strip() for line in m_resp.text.split("\n") if line.strip() and not line.startswith("#")]
        phish_urls.update(m_urls[:10000])
        print(f"    Added {len(m_urls[:10000])} URLs from Maltrail.")
except Exception as e:
    print(f"    Maltrail fetch warning: {e}")

df_phish = pd.DataFrame({"url": list(phish_urls), "label": 1}).drop_duplicates(subset=["url"])
print(f"\nTotal Unique Live Phishing URLs Acquired: {len(df_phish)}")

print("\n" + "=" * 80)
print("2/3 Fetching High-Reputation Legitimate Safe Domains...")
print("=" * 80)

safe_urls = set()
subdomain_prefixes = ["", "www.", "docs.", "developer.", "api.", "blog.", "app.", "support.", "mail.", "m.", "portal.", "store.", "news."]

try:
    print(" -> Fetching OpenDNS Global Top Domains...")
    safe_url = "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt"
    safe_resp = requests.get(safe_url, headers=headers, timeout=12)
    if safe_resp.status_code == 200:
        domains = [line.strip() for line in safe_resp.text.split("\n") if line.strip()]
        for i, d in enumerate(domains[:10000]):
            safe_urls.add("https://" + d)
            # Add realistic subdomains to mirror real-world safe web navigation
            sub = subdomain_prefixes[i % len(subdomain_prefixes)]
            if sub:
                safe_urls.add(f"https://{sub}{d}")
        print(f"    Added top apex domains with realistic subdomains from OpenDNS.")
except Exception as e:
    print(f"    OpenDNS fetch warning: {e}")

indian_verified_safe = [
    "https://netbanking.hdfcbank.com", "https://retail.onlinesbi.sbi.co.in",
    "https://www.icicibank.com", "https://www.axisbank.com", "https://www.kotak.com",
    "https://www.pnbindia.in", "https://bankofbaroda.in", "https://paytm.com",
    "https://phonepe.com", "https://razorpay.com", "https://cashfree.com",
    "https://incometax.gov.in", "https://uidai.gov.in", "https://parivahan.gov.in",
    "https://www.irctc.co.in", "https://epfindia.gov.in", "https://digilocker.gov.in",
    "https://www.amazon.in", "https://www.flipkart.com", "https://www.zomato.com",
    "https://www.swiggy.com", "https://www.cred.club", "https://zerodha.com",
    "https://groww.in", "https://upstox.com", "https://www.tatamotors.com"
]
for u in indian_verified_safe:
    safe_urls.add(u)

df_safe = pd.DataFrame({"url": list(safe_urls), "label": 0}).drop_duplicates(subset=["url"])
print(f"Total Unique Safe URLs Acquired: {len(df_safe)}")

print("\n" + "=" * 80)
print("3/3 Merging & Balancing Enterprise Training Dataset...")
print("=" * 80)

sample_size = min(len(df_phish), len(df_safe))
df_phish_balanced = df_phish.sample(n=sample_size, random_state=42)
df_safe_balanced = df_safe.sample(n=sample_size, random_state=42)

df_merged = pd.concat([df_phish_balanced, df_safe_balanced], ignore_index=True)
df_merged = df_merged.sample(frac=1, random_state=42).reset_index(drop=True)

output_path = DATASETS_DIR / "phishing_urls.csv"
df_merged.to_csv(output_path, index=False)

print(f"\nSuccess! Enterprise Balanced Dataset Created: {output_path}")
print(f"Total Samples: {len(df_merged)}")
print("Class Distribution:\n", df_merged["label"].value_counts())
