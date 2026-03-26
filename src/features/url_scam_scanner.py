# src/features/url_scam_scanner.py

"""
 Offline URL scanner - 8 heuristic rules

 Verdict is based on cumulative risk score:
   >= 5  LIKELY MALICIOUS
   >= 2  SUSPICIOUS
    < 2  SAFE

 Rule sources:
 1.  IP as domain              - University of Denver IT, "5 URL Warning Signs to Watch For", Point 3
                                 https://www.du.edu/it/services/security/5-url-warning-signs
 2.  Brand in subdomain        - TCM Security, "How To Identify URL Phishing Techniques", Subdomain Spoofing section
                                 https://tcm-sec.com/how-to-identify-url-phishing/
                                 University of Denver IT, "5 URL Warning Signs to Watch For", Point 1
                                 https://www.du.edu/it/services/security/5-url-warning-signs
 3.  Typosquatting             - TCM Security, "How To Identify URL Phishing Techniques", Lookalike Domains and Typosquatting section
                                 https://tcm-sec.com/how-to-identify-url-phishing/
 4.  HTTP not HTTPS            - TCM Security, "How To Identify URL Phishing Techniques", Anatomy of a URL — Protocol section
                                 https://tcm-sec.com/how-to-identify-url-phishing/
 5.  Excessive hyphens         - University of Denver IT, "5 URL Warning Signs to Watch For", Point 2
                                 https://www.du.edu/it/services/security/5-url-warning-signs
 6.  URL shortener domain      - TCM Security, "How To Identify URL Phishing Techniques", URL Shortening section
                                 https://tcm-sec.com/how-to-identify-url-phishing/
                                 University of Denver IT, "5 URL Warning Signs to Watch For", Point 4
                                 https://www.du.edu/it/services/security/5-url-warning-signs
 7.  Open redirect             - TCM Security, "How To Identify URL Phishing Techniques", Open Redirects section
                                 https://tcm-sec.com/how-to-identify-url-phishing/
 8.  Suspicious TLD            - Medium, "Threat Hunting - Suspicious TLDs"
                                 https://detect.fyi/threat-hunting-suspicious-tlds-a742c2adbf58
"""

import re
import math
import urllib.parse

# Severity levels
HIGH   = "HIGH"
MEDIUM = "MEDIUM"
LOW    = "LOW"

# List of brands commonly impersonated in phishing attacks
KNOWN_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "facebook", "instagram",
    "netflix", "dropbox", "linkedin", "twitter", "youtube", "whatsapp", "snapchat",
    "tiktok", "ebay", "shopee", "lazada", "walmart", "wellsfargo", "chase", "bdo", "metrobank", "chinabank", "landbank", "dbp", 
    "bpi", "dhl", "fedex", "ups", "usps", "docusign", "adobe", "zoom",
    "steam", "roblox", "discord", "spotify", "airbnb", "uber", "grab",
]

# Known URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.link", "rebrand.ly", "bl.ink", "cutt.ly", "shorturl.at",
    "tiny.cc", "is.gd", "rb.gy", "qr.ae", "clck.ru", "snip.ly",
}

# Query parameter keys commonly used in open redirect attacks
REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "next", "goto",
    "return", "return_url", "dest", "destination", "target",
    "link", "out", "view", "to", "from",
}

# TLDs with disproportionately high abuse rates
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".gq", ".ml", ".cf", ".tk", ".ga",
    ".pw", ".cc", ".su", ".in.net", ".co.cc", ".info", ".biz",
    ".zip", ".mov", ".wav", ".cam", ".skin", ".cyou",
}

# Path keywords strongly associated with phishing pages
PHISHING_PATH_KEYWORDS = [
    "verify", "verification", "validate", "secure", "security",
    "login", "signin", "sign-in", "account", "update", "confirm",
    "billing", "payment", "recover", "unlock", "suspended",
    "unusual-activity", "alert", "notice",
]


# ==========================================
# RULE CHECKS
# ==========================================

def _check_ip_as_domain(parsed) -> dict | None:
    """Rule 1: Raw IP address used as domain (e.g. http://192.168.1.1/login)."""
    hostname = parsed.hostname or ""
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        return {
            "rule":     "IP address as domain",
            "severity": HIGH,
            "detail":   (
                f"The domain is a raw IP address ({hostname}) instead of a named website. "
                f"Legitimate sites always use a domain name. "
                f"There is no way to verify who owns or controls this address."
            ),
            "flag":   "IP as domain",
            "source": "rule",
        }
    return None


def _check_brand_in_subdomain(subdomains: str, domain: str) -> dict | None:
    """Rule 2: Known brand appears in subdomain but registered domain is different."""
    if not subdomains:
        return None
    for brand in KNOWN_BRANDS:
        if brand in subdomains and brand != domain:
            return {
                "rule":     "Brand impersonation in subdomain",
                "severity": HIGH,
                "detail":   (
                    f"'{brand}' appears in the subdomain, but the actual registered "
                    f"domain is '{domain}'. The subdomain is cosmetic — the real "
                    f"destination is controlled by whoever owns '{domain}', not '{brand}'."
                ),
                "flag":   f"Brand spoofed in subdomain ({brand})",
                "source": "rule",
            }
    return None


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein edit distance. Only used for short brand name comparisons."""
    if abs(len(a) - len(b)) > 2:
        return 99
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[j] = prev[j - 1]
            else:
                dp[j] = 1 + min(prev[j], dp[j - 1], prev[j - 1])
    return dp[n]


def _check_typosquatting(domain: str) -> dict | None:
    """Rule 3: Domain is one character away from a known brand."""
    normalized = (
        domain
        .replace("0", "o").replace("1", "l").replace("3", "e")
        .replace("4", "a").replace("5", "s").replace("@", "a")
    )
    for brand in KNOWN_BRANDS:
        if domain == brand:
            continue
        if _edit_distance(normalized, brand) == 1 or _edit_distance(domain, brand) == 1:
            return {
                "rule":     "Possible typosquatting",
                "severity": HIGH,
                "detail":   (
                    f"'{domain}' closely resembles '{brand}' with only one character difference. "
                    f"This is a common technique where a fake domain is registered to "
                    f"impersonate a trusted brand and steal credentials or data."
                ),
                "flag":   f"Typosquatting ({domain} ≈ {brand})",
                "source": "rule",
            }
    return None


def _check_http(parsed) -> dict | None:
    """Rule 4: Plain HTTP instead of HTTPS."""
    if parsed.scheme and parsed.scheme.lower() == "http":
        return {
            "rule":     "Unencrypted HTTP",
            "severity": MEDIUM,
            "detail":   (
                "This URL uses plain HTTP, meaning the connection is not encrypted. "
                "Any data you submit (passwords, payment info) can be intercepted. "
                "All legitimate login, banking, and payment pages use HTTPS."
            ),
            "flag":   "No HTTPS",
            "source": "rule",
        }
    return None


def _check_excessive_hyphens(domain: str) -> dict | None:
    """Rule 5: 3 or more hyphens in domain name."""
    count = domain.count("-")
    if count >= 3:
        return {
            "rule":     "Excessive hyphens in domain",
            "severity": MEDIUM,
            "detail":   (
                f"The domain contains {count} hyphens. "
                f"Legitimate websites rarely use hyphens in their domain name. "
                f"Multiple hyphens are often used to pad a fake domain with "
                f"recognizable words to appear trustworthy."
            ),
            "flag":   f"Excessive hyphens ({count})",
            "source": "rule",
        }
    return None


def _check_url_shortener(hostname: str) -> dict | None:
    """Rule 6: Domain is a known URL shortening service."""
    if hostname.lower() in URL_SHORTENERS:
        return {
            "rule":     "URL shortener detected",
            "severity": MEDIUM,
            "detail":   (
                f"'{hostname}' is a URL shortening service. "
                f"The real destination is hidden behind the short link. "
                f"Use the URL Expander to reveal where it leads before visiting."
            ),
            "flag":             f"URL shortener ({hostname})",
            "source":           "rule",
            "suggest_expander": True,
            "expander_prompt":  (
                f"'{hostname}' is a URL shortener, so the real destination is hidden. "
                f"Use the URL Expander tool to safely reveal where this link leads "
                f"before you visit it."
            ),
        }
    return None


def _check_open_redirect(query: str) -> dict | None:
    """Rule 7: Open redirect parameter detected in query string."""
    if not query:
        return None
    params = {k.lower() for k, *_ in (p.split("=", 1) for p in query.split("&")) if k}
    matched = params & REDIRECT_PARAMS
    if matched:
        found = next(iter(matched))
        return {
            "rule":     "Open redirect parameter in URL",
            "severity": MEDIUM,
            "detail":   (
                f"The URL contains a redirect parameter ('{found}='). "
                f"This can be used to send you to a different site than the one shown. "
                f"The domain may look legitimate, but the redirect destination could be malicious."
            ),
            "flag":   f"Open redirect parameter (?{found}=)",
            "source": "rule",
        }
    return None


def _check_suspicious_tld(hostname: str) -> dict | None:
    """
    Rule 8: TLD or compound suffix is associated with high abuse rates.
    Checks the full hostname suffix so compound TLDs like .in.net are caught.
    """
    lower = hostname.lower()
    for tld in SUSPICIOUS_TLDS:
        if lower.endswith(tld):
            return {
                "rule":     "Suspicious top-level domain",
                "severity": MEDIUM,
                "detail":   (
                    f"This URL uses the '{tld}' TLD, which has a disproportionately "
                    f"high rate of abuse in phishing and malware campaigns. "
                    f"While not conclusive on its own, it is a known risk indicator."
                ),
                "flag":   f"Suspicious TLD ({tld})",
                "source": "rule",
            }
    return None

# ==========================================
# URL PARSER HELPERS
# ==========================================

def _parse(url: str):
    """Parse a URL. Uses https:// only if no scheme is present."""
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = "https://" + url
    try:
        return urllib.parse.urlparse(url), url
    except Exception:
        return None, url


def _get_domain_parts(hostname: str):
    """
    Splits hostname into (subdomains, registered domain, tld).
    e.g. 'login.secure.paypal.com' → ('login.secure', 'paypal', '.com')
    """
    parts = hostname.lower().split(".")
    if len(parts) < 2:
        return "", hostname, ""
    tld        = "." + parts[-1]
    domain     = parts[-2]
    subdomains = ".".join(parts[:-2]) if len(parts) > 2 else ""
    return subdomains, domain, tld


# ==========================================
# SCORING + VERDICT
# ==========================================

_SEVERITY_SCORE     = {HIGH: 3, MEDIUM: 2, LOW: 1}
_VERDICT_THRESHOLDS = {"LIKELY MALICIOUS": 5, "SUSPICIOUS": 2, "SAFE": 0}


def _score_to_verdict(score: int) -> str:
    if score >= _VERDICT_THRESHOLDS["LIKELY MALICIOUS"]:
        return "LIKELY MALICIOUS"
    if score >= _VERDICT_THRESHOLDS["SUSPICIOUS"]:
        return "SUSPICIOUS"
    return "SAFE"


# ==========================================
# SCAN FUNCTION
# ==========================================

def scan_url(url: str) -> dict:
    """
    Full offline URL scan — runs all 8 heuristic rules.

    Flow:
      1. Parse URL → extract hostname, domain, TLD, path, query
      2. Run all 8 rule checks
      3. Score and return verdict

    Shortener hint:
      If Rule 6 fires, the result includes:
        - suggest_expander (bool) : True → UI should offer the URL Expander tool
        - expander_message (str)  : ready-made message to display to the user
    """
    parsed, normalized_url = _parse(url)

    if parsed is None or not parsed.hostname:
        return {
            "url":              url,
            "verdict":          "INVALID",
            "score":            0,
            "flags":            [],
            "rule_flags":       [],
            "error":            "Could not parse URL. Make sure it includes a valid domain.",
            "suggest_expander": False,
            "expander_message": None,
        }

    hostname                = parsed.hostname or ""
    path                    = parsed.path or ""
    query                   = parsed.query or ""
    subdomains, domain, tld = _get_domain_parts(hostname)

    rule_checks = [
        _check_ip_as_domain(parsed),
        _check_brand_in_subdomain(subdomains, domain),
        _check_typosquatting(domain),
        _check_http(parsed),
        _check_excessive_hyphens(domain),
        _check_url_shortener(hostname),
        _check_open_redirect(query),
        _check_suspicious_tld(hostname),
    ]
    rule_flags = [c for c in rule_checks if c is not None]

    score   = sum(_SEVERITY_SCORE.get(f["severity"], 0) for f in rule_flags)
    verdict = _score_to_verdict(score)

    shortener_flag   = next((f for f in rule_flags if f.get("suggest_expander")), None)
    suggest_expander = shortener_flag is not None
    expander_message = shortener_flag.get("expander_prompt") if shortener_flag else None

    return {
        "url":              url,
        "verdict":          verdict,
        "score":            score,
        "flags":            rule_flags,
        "rule_flags":       rule_flags,
        "domain":           domain,
        "tld":              tld,
        "hostname":         hostname,
        "suggest_expander": suggest_expander,
        "expander_message": expander_message,
    }