# tests/test_domain.py
import sys
from pathlib import Path
import joblib

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.domain_engine import compute_risk_score

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

model_path = BASE_DIR / "models" / "domain_xgb.pkl"
model = joblib.load(model_path)

test_urls = [
    # 1. Legitimate Top Apex & Deep URLs
    "https://www.google.com/search?q=astrahackathon",
    "https://github.com/torvalds/linux/commits/master",
    "https://netbanking.hdfcbank.com/netbanking/",
    "https://retail.onlinesbi.sbi.co.in/retail/login.htm",
    
    # 2. Fuzzy Typosquatting (Levenshtein Distance)
    "https://secure-login.hdfbank.com/netbanking/",    # 'hdfbank' (dist 1 to 'hdfcbank')
    "https://hdfccbank-portal.com/login",               # 'hdfccbank' (dist 1 to 'hdfcbank')
    "https://paypa1-security.com/signin",               # 'paypa1' (homoglyph/leetspeak)
    "https://login-sbii.com/account",                   # 'sbii' (dist 1 to 'sbi')
    
    # 3. Abuse of Public Dynamic Hosting (Vercel, Cloudflare Pages, Firebase)
    "https://hdfc-kyc-update.vercel.app/login",
    "https://sbi-rewards-claim.pages.dev/auth",
    "https://netflix-subscription-renew.firebaseapp.com",
    
    # 4. Punycode / IDN Homographs
    "http://xn--gogle-pqa.com/login",
    
    # 5. Classic High-Risk TLD & Direct IP attacks
    "http://192.168.1.100/paypal/signin.php",
    "http://hdfc-kyc-verification-login.top/auth",
    "https://secure-login-sbi-update.xyz/verify-account"
]

print(f"{'URL':<55} | {'Score':<6} | {'Verdict':<12} | {'Reasons'}")
print("=" * 125)

for u in test_urls:
    score, reasons = compute_risk_score(u, model)
    verdict = "[PHISHING]" if score >= 0.5 else "[SAFE]"
    reason_str = ", ".join(reasons) if reasons else "None"
    print(f"{u[:53]:<55} | {score:.2f}  | {verdict:<12} | {reason_str}")
