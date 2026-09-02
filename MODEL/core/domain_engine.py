# core/domain_engine.py
import re
import math
import unicodedata
import requests
from urllib.parse import urlparse
from functools import lru_cache
from typing import Tuple, List, Dict, Any, Optional
import tldextract

TARGET_BRANDS = [
    "hdfc", "hdfcbank", "sbi", "statebank", "icici", "icicibank",
    "axis", "axisbank", "pnb", "bob", "kotak", "paytm", "phonepe",
    "gpay", "razorpay", "paypal", "google", "apple", "amazon",
    "netflix", "microsoft", "flipkart", "swiggy", "zomato", "irctc"
]

TOP_TRUSTED_APEX = {
    "google.com", "github.com", "microsoft.com", "apple.com",
    "amazon.com", "amazon.in", "hdfcbank.com", "icicibank.com",
    "sbi.co.in", "axisbank.com", "kotak.com", "pnbindia.in",
    "paypal.com", "youtube.com", "flipkart.com", "paytm.com",
    "phonepe.com", "razorpay.com", "netflix.com", "irctc.co.in",
    "wikipedia.org", "mozilla.org", "stackoverflow.com", "python.org",
    "pypi.org", "fastapi.tiangolo.com", "tiangolo.com", "cloudflare.com"
}

PUBLIC_SUBDOMAIN_PROVIDERS = {
    "vercel.app", "netlify.app", "pages.dev", "firebaseapp.com",
    "github.io", "glitch.me", "ngrok-free.app", "herokuapp.com",
    "surge.sh", "render.com", "web.app", "workers.dev"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "rest", "buzz", "site", "online",
    "work", "tech", "icu", "club", "info", "tk", "cf", "gq",
    "shop", "live", "link", "guru", "pw", "cc"
}

SUSPICIOUS_KEYWORDS = [
    "secure", "login", "verify", "update", "banking", "kyc",
    "account", "auth", "confirm", "wallet", "suspend", "portal",
    "signin", "support", "recover", "dispute", "alert", "service",
    "pan", "aadhaar", "ebanking", "netbanking", "billpay", "rewards"
]

CONFUSABLE_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'η': 'n', 'ι': 'i',
    'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u',
    'χ': 'x', 'ω': 'w', '0': 'o', '1': 'l', '3': 'e', '4': 'a',
    '5': 's', '8': 'b', '@': 'a', '$': 's'
}

def normalize_punycode_and_homoglyphs(domain_str: str) -> str:
    if not domain_str:
        return ""
    decoded_labels = []
    for label in domain_str.split("."):
        if label.startswith("xn--"):
            try:
                decoded = label.encode("ascii").decode("idna")
                decoded_labels.append(decoded)
            except Exception:
                decoded_labels.append(label)
        else:
            decoded_labels.append(label)

    decoded_domain = ".".join(decoded_labels).lower()
    normalized = unicodedata.normalize("NFKD", decoded_domain)
    output_chars = [CONFUSABLE_MAP.get(ch, ch) for ch in normalized]
    return "".join(output_chars)

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def detect_brand_typosquatting(domain: str, subdomain: str) -> Tuple[Optional[str], int]:
    normalized_domain = normalize_punycode_and_homoglyphs(domain).replace("-", "")
    normalized_sub = normalize_punycode_and_homoglyphs(subdomain).replace("-", "")

    for brand in TARGET_BRANDS:
        if brand in normalized_domain:
            return brand, 0
        if len(normalized_domain) >= 4 and len(brand) >= 4:
            dist = levenshtein_distance(normalized_domain, brand)
            if 1 <= dist <= 2:
                return brand, dist

    for brand in TARGET_BRANDS:
        if brand in normalized_sub:
            return brand, 0
        if len(normalized_sub) >= 4 and len(brand) >= 4:
            dist = levenshtein_distance(normalized_sub, brand)
            if 1 <= dist <= 2:
                return brand, dist

    return None, -1

@lru_cache(maxsize=1024)
def check_domain_age_days(apex_domain: str) -> Optional[int]:
    if not apex_domain or "." not in apex_domain or apex_domain in TOP_TRUSTED_APEX:
        return 9999
    try:
        url = f"https://rdap.org/domain/{apex_domain}"
        resp = requests.get(url, timeout=1.2, headers={"User-Agent": "CyberFraudEngine/1.0"})
        if resp.status_code == 200:
            data = resp.json()
            events = data.get("events", [])
            for ev in events:
                if ev.get("eventAction") in ["registration", "created"]:
                    from datetime import datetime
                    created_str = ev.get("eventDate")
                    if created_str:
                        created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                        now = datetime.now(created_dt.tzinfo)
                        return max(0, (now - created_dt).days)
    except Exception:
        pass
    return None

def resolve_final_landing_url(url: str, max_redirects: int = 4) -> Tuple[str, List[str]]:
    url_str = str(url).strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str
    redirect_chain = [url_str]
    try:
        session = requests.Session()
        resp = session.head(url_str, allow_redirects=True, timeout=1.5, headers={"User-Agent": "Mozilla/5.0"})
        final_url = resp.url
        if final_url != url_str:
            redirect_chain.append(final_url)
        return final_url, redirect_chain
    except Exception:
        return url_str, redirect_chain

def shannon_entropy(string: str) -> float:
    if not string:
        return 0.0
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(string)]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def extract_url_features(url: str) -> dict:
    url_str = str(url).strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str

    try:
        extracted = tldextract.extract(url_str)
        domain = extracted.domain.lower()
        subdomain = extracted.subdomain.lower()
        suffix = extracted.suffix.lower()
        registered_domain = f"{domain}.{suffix}" if suffix else domain

        vowels = set("aeiou")
        vowel_count = sum(1 for c in domain if c in vowels)
        vowel_ratio = vowel_count / max(len(domain), 1)

        max_cons = 0
        curr_cons = 0
        for c in domain:
            if c.isalpha() and c not in vowels:
                curr_cons += 1
                if curr_cons > max_cons:
                    max_cons = curr_cons
            else:
                curr_cons = 0

        features = {
            "domain_length": len(domain),
            "subdomain_length": len(subdomain),
            "subdomain_count": len(subdomain.split(".")) if subdomain else 0,
            "has_ip": 1 if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0,
            "has_punycode": 1 if "xn--" in url_str else 0,
            "domain_hyphens": domain.count("-") + subdomain.count("-"),
            "domain_digits": sum(c.isdigit() for c in domain) + sum(c.isdigit() for c in subdomain),
            "domain_entropy": shannon_entropy(domain),
            "subdomain_entropy": shannon_entropy(subdomain),
            "vowel_ratio": vowel_ratio,
            "max_consecutive_consonants": max_cons,
            "is_suspicious_tld": 1 if suffix in SUSPICIOUS_TLDS else 0,
            "tld_length": len(suffix),
            "keyword_match_count": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in domain or kw in subdomain),
            "brand_match_count": sum(1 for b in TARGET_BRANDS if b in domain or b in subdomain),
            "is_free_hosting": 1 if registered_domain in PUBLIC_SUBDOMAIN_PROVIDERS else 0
        }
        return features
    except Exception:
        return {
            "domain_length": 0, "subdomain_length": 0, "subdomain_count": 0,
            "has_ip": 0, "has_punycode": 0, "domain_hyphens": 0, "domain_digits": 0,
            "domain_entropy": 0.0, "subdomain_entropy": 0.0, "vowel_ratio": 0.0,
            "max_consecutive_consonants": 0, "is_suspicious_tld": 0, "tld_length": 0,
            "keyword_match_count": 0, "brand_match_count": 0, "is_free_hosting": 0
        }

def is_trusted_domain(url: str) -> bool:
    url_str = str(url).strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str
    try:
        extracted = tldextract.extract(url_str)
        registered_domain = f"{extracted.domain.lower()}.{extracted.suffix.lower()}"
        if registered_domain in PUBLIC_SUBDOMAIN_PROVIDERS:
            return False
        return registered_domain in TOP_TRUSTED_APEX
    except Exception:
        return False

def compute_risk_score(
    url: str,
    model: Any = None,
    check_rdap: bool = False,
    follow_redirects: bool = False
) -> Tuple[float, List[str]]:
    reasons = []
    penalty = 0.0

    target_url = url
    if follow_redirects:
        target_url, chain = resolve_final_landing_url(url)
        if len(chain) > 1:
            reasons.append(f"Redirect Chain Followed -> Final: {target_url}")

    if is_trusted_domain(target_url):
        return 0.0, ["Trusted Domain Allowlist"]

    url_str = str(target_url).strip().lower()
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str

    extracted = tldextract.extract(url_str)
    domain_raw = extracted.domain.lower()
    subdomain_raw = extracted.subdomain.lower()
    suffix = extracted.suffix.lower()
    registered_domain = f"{domain_raw}.{suffix}" if suffix else domain_raw

    # Check A: URL Authority Userinfo / '@' Spoofing Trick
    parsed = urlparse(url_str)
    if "@" in parsed.netloc:
        penalty += 0.45
        reasons.append("URL Authority Userinfo Deception ('@' Trick)")

    # Check B: IDN / Punycode Deception
    if "xn--" in url_str:
        penalty += 0.50
        reasons.append("Punycode / IDN Homograph Obfuscation Detected")

    # Check C: Fuzzy Brand Typosquatting & Impersonation
    matched_brand, dist = detect_brand_typosquatting(domain_raw, subdomain_raw)
    if matched_brand:
        if registered_domain not in TOP_TRUSTED_APEX:
            if dist == 0:
                penalty += 0.60
                reasons.append(f"Brand Impersonation Target ({matched_brand.upper()})")
            elif dist in (1, 2):
                penalty += 0.70
                reasons.append(f"Fuzzy Typosquatting Target ({matched_brand.upper()}, Edit Distance {dist})")

    # Check D: Suspicious / Low-Cost TLD
    if suffix in SUSPICIOUS_TLDS:
        penalty += 0.35
        reasons.append(f"High-Risk TLD (.{suffix})")

    # Check E: Raw IP Host
    if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_raw):
        penalty += 0.75
        reasons.append("Direct IP Host (No Domain)")

    # Check F: Excessive Hyphens / Subdomain Abuse
    domain_full = f"{subdomain_raw}.{domain_raw}" if subdomain_raw else domain_raw
    if domain_full.count("-") >= 2:
        penalty += 0.30
        reasons.append("High Hyphen Obfuscation")

    if len(subdomain_raw.split(".")) >= 3:
        penalty += 0.25
        reasons.append("Deep Multi-Subdomain Nesting")

    # Check G: High Entropy / DGA / Random String Obfuscation
    ent = shannon_entropy(domain_raw)
    digits_ratio = sum(c.isdigit() for c in domain_raw) / max(len(domain_raw), 1)
    if (len(domain_raw) >= 18 and ent >= 3.6) or (len(domain_raw) >= 15 and digits_ratio >= 0.30):
        penalty += 0.50
        reasons.append(f"High-Entropy / DGA Algorithm Pattern (Entropy: {ent:.2f})")

    # Check H: Phishing / Security Keywords
    kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain_full]
    if kw_hits:
        penalty += min(0.40, len(kw_hits) * 0.15)
        reasons.append(f"Suspicious Security Keywords: {kw_hits[:3]}")

    # Check I: Public Subdomain Platform Hosting
    if registered_domain in PUBLIC_SUBDOMAIN_PROVIDERS:
        if kw_hits or matched_brand:
            penalty += 0.50
            reasons.append(f"Abuse of Free Hosting Platform ({registered_domain})")

    # Check J: Domain Age (RDAP)
    if check_rdap:
        age_days = check_domain_age_days(registered_domain)
        if age_days is not None:
            if age_days < 14:
                penalty += 0.55
                reasons.append(f"Newly Registered Domain (< 14 days old: {age_days}d)")
            elif age_days < 60:
                penalty += 0.30
                reasons.append(f"Recent Domain (< 60 days old: {age_days}d)")

    # ML Classifier Evaluation
    ml_prob = 0.0
    if model is not None:
        import pandas as pd
        features = pd.DataFrame([extract_url_features(target_url)])
        ml_prob = float(model.predict_proba(features)[0][1])

    final_score = round(min(1.0, max(ml_prob, penalty)), 2)

    if final_score >= 0.5 and not reasons:
        reasons.append("Statistical ML Feature Anomaly")

    return final_score, reasons
