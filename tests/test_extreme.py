# tests/test_extreme.py
import sys
from pathlib import Path
import joblib

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.domain_engine import compute_risk_score, is_trusted_domain

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

model = joblib.load(BASE_DIR / "models" / "domain_xgb.pkl")

extreme_test_suite = [
    # --- Category 1: URL Basic Auth & Userinfo Trick ---
    {
        "category": "Basic Auth / Userinfo Trick",
        "url": "https://www.google.com:login-secure@evil-phishing-portal.xyz/auth",
        "expected": "PHISHING"
    },
    {
        "category": "Basic Auth / Userinfo Trick",
        "url": "https://hdfcbank.com@verification-pan-kyc.site/login",
        "expected": "PHISHING"
    },

    # --- Category 2: Reverse Subdomain Brand Masking ---
    {
        "category": "Reverse Subdomain Masking",
        "url": "https://hdfcbank.com.security-update.xyz/netbanking",
        "expected": "PHISHING"
    },
    {
        "category": "Reverse Subdomain Masking",
        "url": "https://www.sbi.co.in.customer-service-portal.online/update",
        "expected": "PHISHING"
    },

    # --- Category 3: Deep Multi-Subdomain & Hyphen Flooding ---
    {
        "category": "Multi-Subdomain Flooding",
        "url": "https://login.secure.verify.account.update.kyc.portal.hdfc-bank-auth.click/",
        "expected": "PHISHING"
    },
    {
        "category": "Hyphen Obfuscation",
        "url": "https://s-b-i-c-a-r-d-k-y-c-u-p-d-a-t-e.top/login",
        "expected": "PHISHING"
    },

    # --- Category 4: Unicode / Cyrillic Homoglyph Injection ---
    {
        "category": "Cyrillic Homoglyph",
        "url": "https://www.gооgle.com/search",
        "expected": "PHISHING"
    },
    {
        "category": "Punycode Homoglyph",
        "url": "https://xn--pypal-4ve.com/signin",
        "expected": "PHISHING"
    },

    # --- Category 5: Typosquatting / Visual Leetspeak ---
    {
        "category": "Fuzzy Typosquatting",
        "url": "https://www.hdfcbnk.com/netbanking",
        "expected": "PHISHING"
    },
    {
        "category": "Fuzzy Typosquatting",
        "url": "https://icicbbank.com/login",
        "expected": "PHISHING"
    },
    {
        "category": "Leetspeak Character Swap",
        "url": "https://paypa1-security.com/webscr",
        "expected": "PHISHING"
    },

    # --- Category 6: Dynamic Cloud / Serverless Free Host Abuse ---
    {
        "category": "Free Cloud Hosting Abuse",
        "url": "https://hdfc-bank-kyc-reactivate.pages.dev/auth",
        "expected": "PHISHING"
    },
    {
        "category": "Free Cloud Hosting Abuse",
        "url": "https://sbi-card-reward-points.vercel.app/claim",
        "expected": "PHISHING"
    },
    {
        "category": "Free Cloud Hosting Abuse",
        "url": "https://instant-paytm-refund.firebaseapp.com/wallet",
        "expected": "PHISHING"
    },

    # --- Category 7: Direct IP Hosts & Non-Standard Ports ---
    {
        "category": "Direct IP with Port",
        "url": "http://185.220.101.5:8080/hdfc/login.html",
        "expected": "PHISHING"
    },
    {
        "category": "Direct Local IP Bypass",
        "url": "http://127.0.0.1/admin/login",
        "expected": "PHISHING"
    },

    # --- Category 8: DGA / High Entropy Random Strings ---
    {
        "category": "High-Entropy DGA",
        "url": "https://x892jklms7df98234nkjsdf9823.xyz/track",
        "expected": "PHISHING"
    },

    # --- Category 9: Legitimate Deep URLs ---
    {
        "category": "Legit Deep Subdomain (Safe)",
        "url": "https://retail.onlinesbi.sbi.co.in/retail/login.htm",
        "expected": "SAFE"
    },
    {
        "category": "Legit Complex Query (Safe)",
        "url": "https://www.google.com/search?hl=en&q=hdfc+netbanking+login&source=hp",
        "expected": "SAFE"
    },
    {
        "category": "Legit Developer Deep Path (Safe)",
        "url": "https://github.com/torvalds/linux/blob/master/include/linux/types.h",
        "expected": "SAFE"
    },
    {
        "category": "Legit E-Commerce Nested URL (Safe)",
        "url": "https://www.amazon.in/gp/buy/spc/handlers/display.html?hasWorkingJavascript=1",
        "expected": "SAFE"
    }
]

print("=" * 135)
print(f"{'Category':<28} | {'Score':<6} | {'Status':<10} | {'Test URL':<45} | {'Reasons'}")
print("=" * 135)

passed = 0
failed = 0

for item in extreme_test_suite:
    url = item["url"]
    score, reasons = compute_risk_score(url, model)
    actual = "PHISHING" if score >= 0.5 else "SAFE"
    status_icon = "PASS" if actual == item["expected"] else "FAIL"
    
    if status_icon == "PASS":
        passed += 1
    else:
        failed += 1

    reasons_str = "; ".join(reasons) if reasons else "None"
    print(f"{item['category']:<28} | {score:.2f}  | {status_icon:<10} | {url[:43]:<45} | {reasons_str}")

print("=" * 135)
print(f"Results: {passed}/{len(extreme_test_suite)} Extreme Tests PASSED ({failed} Failed)")
