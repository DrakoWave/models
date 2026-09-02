# core/sms_engine.py
import re
from typing import Optional, Dict, Any, List
import joblib
from core.domain_engine import compute_risk_score as compute_domain_risk

SMS_PANIC_KEYWORDS = [
    "suspended", "deactivated", "blocked", "disconnected", "cutoff",
    "power cutoff", "electricity", "kyc", "pan card", "challan",
    "apk", "lottery", "cashback", "reward", "congratulations",
    "urgent", "immediately", "within 24 hours", "unblock", "overdue"
]

URL_REGEX = r"(?i)\b(?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’])"

def extract_urls_from_text(text: str) -> List[str]:
    found_urls = []
    for match in re.finditer(URL_REGEX, text):
        found_urls.append(match.group(0))
    return found_urls

def compute_sms_risk_score(
    text: str,
    sms_bundle: dict,
    domain_model: Optional[Any] = None,
    sender: str = ""
) -> Dict[str, Any]:
    text_clean = str(text).strip()
    vectorizer = sms_bundle["vectorizer"]
    classifier = sms_bundle["classifier"]

    X_vec = vectorizer.transform([text_clean])
    ml_prob = float(classifier.predict_proba(X_vec)[0][1])

    reasons = []
    penalty = 0.0

    text_lower = text_clean.lower()
    matched_kws = [kw for kw in SMS_PANIC_KEYWORDS if kw in text_lower]
    if matched_kws:
        penalty += min(0.35, len(matched_kws) * 0.12)
        reasons.append(f"Urgency / Financial Panic Trigger: {matched_kws[:3]}")

    if ".apk" in text_lower:
        penalty += 0.40
        reasons.append("Malicious Android Package (.APK) link lure")

    urls = extract_urls_from_text(text_clean)
    url_scan_results = []
    max_url_risk = 0.0
    all_urls_trusted = len(urls) > 0

    for u in urls:
        if domain_model is not None:
            url_score, url_reasons = compute_domain_risk(u, domain_model)
            url_scan_results.append({
                "url": u,
                "risk_score": round(url_score, 2),
                "is_phishing": url_score >= 0.5,
                "reasons": url_reasons
            })
            if url_score > max_url_risk:
                max_url_risk = url_score
            if url_score > 0.0:
                all_urls_trusted = False
        else:
            url_scan_results.append({"url": u, "risk_score": 0.0, "reasons": ["Domain model not loaded"]})
            all_urls_trusted = False

    is_transactional_text = any(
        kw in text_lower for kw in ["debited", "credited", "neft", "otp for", "one time password", "avail bal", "inr ", "rs "]
    )

    if max_url_risk >= 0.5:
        penalty += 0.50
        reasons.append("Contains High-Risk / Phishing URL")

    if all_urls_trusted and not matched_kws and ".apk" not in text_lower:
        ml_prob = min(ml_prob, 0.15)
        reasons = ["Legitimate Bank Domain Link"]

    if is_transactional_text and not matched_kws and not urls:
        raw_score = min(ml_prob, 0.20)
    elif all_urls_trusted and not matched_kws:
        raw_score = min(ml_prob, 0.20)
    else:
        raw_score = max(ml_prob, penalty, max_url_risk)
        if ml_prob >= 0.5 and max_url_risk >= 0.5:
            raw_score = 1.0

    final_score = round(min(1.0, raw_score), 2)
    is_threat = final_score >= 0.50
    verdict = "SMISHING" if is_threat else "LEGITIMATE"

    if is_threat and not reasons:
        reasons.append("Statistical Smishing Text Anomaly")

    return {
        "sender": sender,
        "message": text_clean,
        "risk_score": final_score,
        "verdict": verdict,
        "is_threat": is_threat,
        "sms_ml_score": round(ml_prob, 2),
        "embedded_urls": url_scan_results,
        "reasons": reasons,
        "action": "BLOCK_AND_ALERT" if final_score >= 0.75 else ("WARN_USER" if is_threat else "ALLOW")
    }
