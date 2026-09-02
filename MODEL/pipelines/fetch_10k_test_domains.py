# pipelines/fetch_10k_test_domains.py
"""
Fetches 10,000 balanced domain testing URLs (5,000 phishing + 5,000 safe)
and saves them strictly for testing in:
datasets/domain_test_10k.csv

STRICT: THIS SCRIPT DOES NOT TRAIN OR RETRAIN ANY MODEL.
"""
import io
import time
from pathlib import Path
import requests
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATASETS_DIR = BASE_DIR / "datasets"
DATASETS_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_CSV = DATASETS_DIR / "domain_test_10k.csv"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestDatasetFetcher/1.0"}

print("=" * 80)
print("1/3 Fetching ~5,000 Phishing & Malicious URLs for Testing...")
print("=" * 80)

phish_urls = set()

# Source 1: OpenPhish Live Feed
try:
    print(" -> Fetching OpenPhish live stream...")
    resp = requests.get("https://openphish.com/feed.txt", headers=headers, timeout=15)
    if resp.status_code == 200:
        links = [line.strip() for line in resp.text.split("\n") if line.strip().startswith("http")]
        phish_urls.update(links)
        print(f"    Added {len(links)} URLs from OpenPhish.")
except Exception as e:
    print(f"    Warning OpenPhish: {e}")

# Source 2: URLhaus Live Database
try:
    print(" -> Fetching URLhaus live database...")
    urlhaus_resp = requests.get("https://urlhaus.abuse.ch/downloads/csv_online/", headers=headers, timeout=15)
    if urlhaus_resp.status_code == 200:
        count = 0
        for line in urlhaus_resp.text.split("\n"):
            if line and not line.startswith("#"):
                parts = line.split('","')
                if len(parts) > 2 and parts[2].startswith("http"):
                    clean_u = parts[2].replace('"', '').strip()
                    phish_urls.add(clean_u)
                    count += 1
                    if count >= 6000:
                        break
        print(f"    Added {count} URLs from URLhaus.")
except Exception as e:
    print(f"    Warning URLhaus: {e}")

# Source 3: Maltrail Malicious Domains (as fallback/additional source)
if len(phish_urls) < 5000:
    try:
        print(" -> Fetching Maltrail Malicious Domains feed...")
        m_resp = requests.get("https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt", headers=headers, timeout=15)
        if m_resp.status_code == 200:
            for line in m_resp.text.split("\n"):
                clean = line.strip()
                if clean and not clean.startswith("#"):
                    phish_urls.add("http://" + clean)
                if len(phish_urls) >= 6000:
                    break
            print(f"    Total phishing pool size: {len(phish_urls)}")
    except Exception as e:
        print(f"    Warning Maltrail: {e}")

df_phish = pd.DataFrame({"url": list(phish_urls), "label": 1}).drop_duplicates(subset=["url"])
print(f"Total Phishing Test Samples Collected: {len(df_phish)}")

print("\n" + "=" * 80)
print("2/3 Fetching ~5,000 High-Reputation Safe URLs for Testing...")
print("=" * 80)

safe_urls = set()
subdomain_prefixes = ["", "www.", "docs.", "developer.", "api.", "blog.", "app.", "support.", "mail.", "m.", "portal.", "store.", "news."]

# Source: OpenDNS Global Top Domains
try:
    print(" -> Fetching OpenDNS Global Top Domains...")
    safe_url = "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt"
    safe_resp = requests.get(safe_url, headers=headers, timeout=15)
    if safe_resp.status_code == 200:
        domains = [line.strip() for line in safe_resp.text.split("\n") if line.strip()]
        for i, d in enumerate(domains):
            sub = subdomain_prefixes[i % len(subdomain_prefixes)]
            if sub:
                safe_urls.add(f"https://{sub}{d}")
            else:
                safe_urls.add(f"https://{d}")
            if len(safe_urls) >= 6000:
                break
        print(f"    Added {len(safe_urls)} safe URLs from OpenDNS.")
except Exception as e:
    print(f"    Warning OpenDNS: {e}")

df_safe = pd.DataFrame({"url": list(safe_urls), "label": 0}).drop_duplicates(subset=["url"])
print(f"Total Safe Test Samples Collected: {len(df_safe)}")

print("\n" + "=" * 80)
print("3/3 Merging Exactly 10,000 Balanced Testing Samples (5,000 Safe / 5,000 Phishing)...")
print("=" * 80)

target_per_class = min(5000, len(df_phish), len(df_safe))
df_phish_5k = df_phish.sample(n=target_per_class, random_state=99)
df_safe_5k = df_safe.sample(n=target_per_class, random_state=99)

df_10k = pd.concat([df_phish_5k, df_safe_5k], ignore_index=True)
df_10k = df_10k.sample(frac=1, random_state=99).reset_index(drop=True)

df_10k.to_csv(OUTPUT_CSV, index=False)

print(f"\nSUCCESS! Created Test Dataset CSV: {OUTPUT_CSV}")
print(f"Total Rows: {len(df_10k)}")
print("Class Distribution:")
print(df_10k["label"].value_counts())
