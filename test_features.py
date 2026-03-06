"""
GonePhishing - Phishing Detection System
tests/test_features.py - Unit tests for feature extraction
Run with: pytest tests/test_features.py -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from feature_extractor import extract_features, URL_FEATURE_NAMES, EMAIL_FEATURE_NAMES


# ── URL Tests ──────────────────────────────────────────────────────────────────

class TestURLFeatures:

    def test_returns_correct_length(self):
        features = extract_features("http://example.com", "url")
        assert len(features) == 15, "Should return 15 features for URL"

    def test_https_flag_true(self):
        features = extract_features("https://example.com", "url")
        assert features[3] == 1, "HTTPS flag should be 1 for https URL"

    def test_https_flag_false(self):
        features = extract_features("http://example.com", "url")
        assert features[3] == 0, "HTTPS flag should be 0 for http URL"

    def test_ip_address_detected(self):
        features = extract_features("http://192.168.1.1/login", "url")
        assert features[2] == 1, "Should detect IP address in URL"

    def test_no_ip_address(self):
        features = extract_features("https://google.com", "url")
        assert features[2] == 0, "Should not flag domain-based URL as IP"

    def test_suspicious_tld_detected(self):
        features = extract_features("http://phishing-site.xyz/login", "url")
        assert features[9] == 1, "Should detect suspicious TLD .xyz"

    def test_known_safe_domain(self):
        features = extract_features("https://google.com/search", "url")
        assert features[10] == 1, "Should flag google.com as safe domain"

    def test_url_length_calculated(self):
        url = "http://example.com"
        features = extract_features(url, "url")
        assert features[0] == len(url), "URL length should match actual length"

    def test_at_symbol_detected(self):
        features = extract_features("http://attacker.com@legitimate.com", "url")
        assert features[6] >= 1, "Should detect @ symbol in URL"

    def test_phishing_keyword_in_url(self):
        features = extract_features("http://example.com/verify-account", "url")
        assert features[11] == 1, "Should detect phishing keyword 'verify' in URL"

    def test_safe_url_all_zeros(self):
        """A clean HTTPS URL should have mostly safe indicators."""
        features = extract_features("https://bbc.co.uk/news", "url")
        assert features[3] == 1, "BBC uses HTTPS"
        assert features[2] == 0, "BBC URL has no IP address"


# ── Email Tests ────────────────────────────────────────────────────────────────

class TestEmailFeatures:

    def test_returns_correct_length(self):
        features = extract_features("Hello this is a test email.", "email")
        assert len(features) == 15, "Should return 15 features for email"

    def test_phishing_keywords_counted(self):
        email = "Please verify your account urgently and confirm your password."
        features = extract_features(email, "email")
        assert features[2] > 0, "Should detect phishing keywords"

    def test_urgent_language_detected(self):
        email = "URGENT: Act now or your account will be closed immediately!"
        features = extract_features(email, "email")
        assert features[3] > 0, "Should detect urgent language"

    def test_url_count_detected(self):
        email = "Click here: http://phishing.xyz and also http://fake.tk"
        features = extract_features(email, "email")
        assert features[1] == 2, "Should count 2 URLs in email"

    def test_no_urls_in_safe_email(self):
        email = "Hi, just checking in. Hope you have a great day!"
        features = extract_features(email, "email")
        assert features[1] == 0, "Safe email should have 0 URLs"

    def test_credential_request_detected(self):
        email = "Please enter your password and credentials to verify."
        features = extract_features(email, "email")
        assert features[6] == 1, "Should detect credential request"

    def test_financial_language_detected(self):
        email = "Your bank account requires a £500 transfer immediately."
        features = extract_features(email, "email")
        assert features[7] == 1, "Should detect financial language"

    def test_html_tags_detected(self):
        email = "<html><body><a href='http://phishing.xyz'>Click here</a></body></html>"
        features = extract_features(email, "email")
        assert features[11] == 1, "Should detect HTML tags in email"

    def test_empty_email(self):
        features = extract_features("", "email")
        assert len(features) == 15, "Empty email should still return 15 features"


# ── General Tests ──────────────────────────────────────────────────────────────

class TestGeneral:

    def test_feature_names_match_count_url(self):
        assert len(URL_FEATURE_NAMES) == 15, "Should have 15 URL feature names"

    def test_feature_names_match_count_email(self):
        assert len(EMAIL_FEATURE_NAMES) == 15, "Should have 15 email feature names"

    def test_all_features_are_numeric(self):
        features = extract_features("https://example.com", "url")
        for f in features:
            assert isinstance(f, (int, float)), f"Feature {f} should be numeric"

    def test_url_without_scheme(self):
        """Should handle URLs without http:// prefix."""
        features = extract_features("example.com/login", "url")
        assert len(features) == 15, "Should handle URL without scheme"
