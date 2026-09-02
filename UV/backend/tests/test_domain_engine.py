# tests/test_domain_engine.py
import pytest
from unittest.mock import patch
import requests

from domain_engine import (
    extract_url_features,
    is_shared_hosting,
    check_domain_age,
    expand_shortened_url,
    get_domain_verdict
)

def test_feature_extractor_never_raises_on_malformed_input():
    """Verify feature extractor handles None, empty strings, and garbage input safely."""
    inputs = [None, "", "   ", "not_a_url", "http://", "https://:::"]
    for inp in inputs:
        features = extract_url_features(inp)
        assert isinstance(features, dict)
        assert len(features) == 16
        assert all(isinstance(v, (int, float)) for v in features.values())
        assert features["domain_length"] >= 0

def test_is_shared_hosting_identifies_providers():
    """Verify is_shared_hosting accurately flags Vercel, Netlify, and other cloud subdomains."""
    assert is_shared_hosting("vercel.app", "my-phish-app") is True
    assert is_shared_hosting("netlify.app", "secure-sbi-portal") is True
    assert is_shared_hosting("firebaseapp.com", "login-auth") is True
    assert is_shared_hosting("google.com", "www") is False
    assert is_shared_hosting("hdfcbank.com", "netbanking") is False

@patch("whois.whois")
def test_check_domain_age_fails_open_on_whois_error(mock_whois):
    """Verify check_domain_age returns a clean fallback dictionary without raising on network/WHOIS errors."""
    mock_whois.side_effect = Exception("WHOIS Server Connection Refused / Timeout")
    
    result = check_domain_age("http://unreachable-domain-12345.com")
    assert isinstance(result, dict)
    assert result["age_days"] is None
    assert result["is_new"] is False
    assert result["trust_age_signal"] is False
    assert result["shared_hosting"] is False

@patch("whois.whois")
def test_check_domain_age_bypasses_whois_for_shared_hosting(mock_whois):
    """Assert WHOIS is NEVER called when inspecting a shared hosting platform."""
    result = check_domain_age("https://sbi-kyc.vercel.app/login")
    assert result["shared_hosting"] is True
    assert result["is_new"] is False
    assert mock_whois.call_count == 0  # WHOIS MUST NOT be called!

@patch("requests.Session.head")
def test_expand_shortened_url_fails_open_on_timeout(mock_head):
    """Verify shortened URL expansion fails open on network timeouts without raising."""
    mock_head.side_effect = requests.exceptions.Timeout("Connection timed out")
    
    result = expand_shortened_url("http://bit.ly/fake-link", timeout=1.0)
    assert isinstance(result, dict)
    assert result["resolved"] is False
    assert "bit.ly/fake-link" in result["final_url"]
    assert "error" in result

def test_domain_verdict_malformed_input_fails_open():
    """Ensure get_domain_verdict returns a SAFE response without crashing on bad inputs."""
    res = get_domain_verdict("invalid_url_string", None)
    assert res.verdict in ["SAFE", "SUSPICIOUS"]
    assert 0.0 <= res.confidence <= 1.0
    assert isinstance(res.reasons, list)
    assert res.detail is not None
