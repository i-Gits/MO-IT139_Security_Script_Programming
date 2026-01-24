# src/features/webform_validator.py
import re

def classify_input(value: str) -> tuple[str, str, str]:
    """
    Classify a single input string.
    Returns: (kind, message, severity) where severity is 'good', 'warning', or 'bad'
    """
    value_lower = value.lower()

    # ── URL check ──
    if re.match(r'^https?://', value):
        if any(x in value_lower for x in ['<script>', 'javascript:', 'onerror=', 'onload=']):
            return "URL", "Potentially malicious (script tag / js scheme detected)", "bad"
        if re.search(r'\b(admin|login|wp-admin|phpmyadmin)\b', value_lower):
            return "URL", "Looks like admin/login panel — exercise caution", "warning"
        return "URL", "Ordinary-looking URL", "good"

    # ── Email check ──
    if re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', value):
        disposable_domains = [
            '@temp-mail.org', '@guerrillamail.com', '@10minutemail.com',
            '@mailinator.com', '@yopmail.com', '@trashmail.com'
        ]
        if any(domain in value_lower for domain in disposable_domains):
            return "Email", "Disposable / temporary email service", "warning"
        return "Email", "Valid-looking email address", "good"

    # ── XSS / injection patterns ──
    xss_patterns = [
        "<script", "javascript:", "alert(", "onerror=", "onload=",
        "document.cookie", "eval(", "base64", "fromCharCode",
        "innerHTML", "outerHTML", "srcdoc"
    ]
    if any(p in value_lower for p in xss_patterns):
        return "Input", "Contains potential XSS / injection pattern", "bad"

    # ── SQL injection fragments ──
    sql_patterns = [
        "' or '1'='1", "union select", "drop table", "--", ";--",
        "';", "or 1=1", "admin' --"
    ]
    if any(p in value_lower for p in sql_patterns):
        return "Input", "Contains classic SQL injection pattern", "bad"

    # Default — clean
    return "Input", "No obvious red flags", "good"


def validate_inputs(raw_text: str) -> dict:
    """
    Validate multiple lines of input.
    Returns a dict with summary and per-line results for GUI display.
    """
    if not raw_text.strip():
        return {
            "summary": "No input provided.",
            "summary_color": "gray",
            "lines": []
        }

    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]

    results = []
    good_count = 0
    issues = []

    for idx, value in enumerate(lines, 1):
        kind, message, severity = classify_input(value)
        truncated = value[:60] + ('...' if len(value) > 60 else '')

        line_result = {
            "line_num": idx,
            "value": truncated,
            "full_value": value,
            "kind": kind,
            "message": message,
            "severity": severity
        }

        if severity == "good":
            good_count += 1
        else:
            issues.append(line_result)

        results.append(line_result)

    total = len(lines)
    if good_count == total:
        summary = f"Checked {total} input(s) — All look clean ✓"
        summary_color = "#22c55e"  # green
    elif good_count > total // 2:
        summary = f"Checked {total} input(s) — {good_count} good, some concerns"
        summary_color = "#f59e0b"  # orange
    else:
        summary = f"Checked {total} input(s) — {len(issues)} potentially unsafe"
        summary_color = "#ef4444"  # red

    return {
        "summary": summary,
        "summary_color": summary_color,
        "lines": results,
        "good_count": good_count,
        "total": total
    }