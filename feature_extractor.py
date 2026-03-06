"""
GonePhishing - Phishing Detection System
feature_extractor.py - Extracts ML features from URLs and email content
"""

import re
import urllib.parse


# ── Suspicious indicators ──────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".top", ".click", ".link", ".online", ".site", ".club"
}

PHISHING_KEYWORDS = [
    "verify", "urgent", "suspended", "confirm", "update", "account",
    "security", "alert", "click here", "login", "sign in", "validate",
    "unusual activity", "limited time", "act now", "immediately",
    "password", "credential", "bank", "paypal", "amazon", "microsoft",
    "apple", "netflix", "invoice", "payment", "refund", "prize", "won"
]

SAFE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "bbc.co.uk", "gov.uk", "nhs.uk", "youtube.com", "github.com"
}


# ── Main function ──────────────────────────────────────────────────────────────
def extract_features(input_text, input_type="url"):
    """
    Extract numerical features from a URL or email string.

    Args:
        input_text (str): The URL or email content to analyse
        input_type (str): "url" or "email"

    Returns:
        list: Feature vector (list of numbers) for the ML model
    """
    if input_type == "url":
        return _extract_url_features(input_text.strip())
    else:
        return _extract_email_features(input_text.strip())


# ── URL Features ───────────────────────────────────────────────────────────────
def _extract_url_features(url):
    """Extract 15 numerical features from a URL."""

    # Ensure URL has a scheme for parsing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        full   = url.lower()
    except Exception:
        return [0] * 15

    features = [
        # 1. URL length (longer = more suspicious)
        len(url),

        # 2. Domain length
        len(domain),

        # 3. Has IP address instead of domain name (red flag)
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0,

        # 4. Uses HTTPS (0 = suspicious, 1 = safer)
        1 if url.startswith("https") else 0,

        # 5. Count of dots in domain (many subdomains = suspicious)
        domain.count("."),

        # 6. Count of hyphens in domain
        domain.count("-"),

        # 7. Count of @ symbols (used to trick browsers)
        full.count("@"),

        # 8. Count of // in path (redirect trick)
        path.count("//"),

        # 9. Count of special characters (?, =, &, %)
        sum(full.count(c) for c in ["?", "=", "&", "%"]),

        # 10. Suspicious TLD (e.g. .xyz, .tk, .ml)
        1 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0,

        # 11. Known safe domain
        1 if any(domain.endswith(sd) for sd in SAFE_DOMAINS) else 0,

        # 12. Phishing keyword in URL
        1 if any(kw in full for kw in ["login", "verify", "secure", "account", "update", "banking"]) else 0,

        # 13. Subdomain depth (count dots before main domain)
        max(0, domain.count(".") - 1),

        # 14. Path length
        len(path),

        # 15. Has port number in URL
        1 if re.search(r':\d{2,5}', domain) else 0,
    ]

    return features


# ── Email Features ─────────────────────────────────────────────────────────────
def _extract_email_features(email_text):
    """Extract 15 numerical features from email content."""

    text_lower = email_text.lower()

    # Find all URLs in the email
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text_lower)

    # Find sender domain if email headers are included
    sender_match = re.search(r'from:.*?@([\w.-]+)', text_lower)
    sender_domain = sender_match.group(1) if sender_match else ""

    features = [
        # 1. Total character length of email
        len(email_text),

        # 2. Number of URLs in email
        len(urls),

        # 3. Number of phishing keywords found
        sum(1 for kw in PHISHING_KEYWORDS if kw in text_lower),

        # 4. Urgent language score (count urgent phrases)
        sum(1 for phrase in ["urgent", "immediately", "act now", "limited time", "expires"] if phrase in text_lower),

        # 5. Contains suspicious TLD in any URL
        1 if any(any(url.find(tld) != -1 for tld in SUSPICIOUS_TLDS) for url in urls) else 0,

        # 6. Number of exclamation marks (pressure tactics)
        email_text.count("!"),

        # 7. Contains password/credential requests
        1 if any(word in text_lower for word in ["password", "credentials", "username", "login details"]) else 0,

        # 8. Contains money/financial language
        1 if any(word in text_lower for word in ["£", "$", "€", "bank", "transfer", "payment", "invoice", "refund"]) else 0,

        # 9. Contains threat language
        1 if any(phrase in text_lower for phrase in ["account suspended", "will be closed", "verify now", "or else"]) else 0,

        # 10. Sender domain is suspicious (if found)
        1 if sender_domain and any(sender_domain.endswith(tld.lstrip(".")) for tld in SUSPICIOUS_TLDS) else 0,

        # 11. Mismatch between display text and URLs (basic check)
        1 if len(urls) > 0 and any(word in text_lower for word in ["click here", "click below", "follow this link"]) else 0,

        # 12. Contains HTML tags (HTML-only phishing email)
        1 if re.search(r'<[a-z]+>', text_lower) else 0,

        # 13. Very short email with link (suspicious)
        1 if len(email_text) < 200 and len(urls) > 0 else 0,

        # 14. High ratio of URLs to total words
        min(len(urls) / max(len(email_text.split()), 1) * 100, 100),

        # 15. Number of capital letters (shouty = pressure tactic)
        sum(1 for c in email_text if c.isupper()),
    ]

    return features


# ── Feature names (for model trainer + reporting) ──────────────────────────────
URL_FEATURE_NAMES = [
    "url_length", "domain_length", "has_ip_address", "uses_https",
    "dot_count", "hyphen_count", "at_symbol_count", "double_slash_count",
    "special_char_count", "suspicious_tld", "known_safe_domain",
    "phishing_keyword_in_url", "subdomain_depth", "path_length", "has_port"
]

EMAIL_FEATURE_NAMES = [
    "email_length", "url_count", "phishing_keyword_count", "urgent_phrase_count",
    "suspicious_tld_in_url", "exclamation_count", "credential_request",
    "financial_language", "threat_language", "suspicious_sender_domain",
    "click_here_language", "has_html_tags", "short_email_with_link",
    "url_word_ratio", "capital_letter_count"
]


# ── Quick test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_url = "http://secure-login.paypal.com.suspicious-domain.xyz/verify?account=update"
    features = extract_features(test_url, "url")
    print("URL Features:")
    for name, val in zip(URL_FEATURE_NAMES, features):
        print(f"  {name:<30} {val}")

    print()
    test_email = "URGENT: Your account has been suspended! Click here to verify your password immediately or your account will be closed. http://login-verify.tk/paypal"
    features = extract_features(test_email, "email")
    print("Email Features:")
    for name, val in zip(EMAIL_FEATURE_NAMES, features):
        print(f"  {name:<30} {val}")
