# src/features/webform_validator.py
# With additional email validation (Ref: https://whoapi.com/blog/understanding-valid-email-address-formats-a-short-guide/)

import re
import html

# ── SQL injection keywords to detect and block ──
SQL_KEYWORDS = [
    "SELECT", "DROP", "INSERT", "DELETE", "UPDATE", "UNION",
    "CREATE", "ALTER", "EXEC", "EXECUTE", "SCRIPT", "JAVASCRIPT",
    "ONCLICK", "ONERROR", "ONLOAD", "--", "/*", "*/",
    "OR 1=1", "OR '1'='1", "';", "UNION SELECT", ";--"
]

# ── XSS and malicious code patterns (regex) ──
DANGEROUS_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'<img[^>]*onerror[^>]*>',
    r'<img[^>]*onclick[^>]*>',
    r'<iframe[^>]*>',
    r'javascript:',
    r'on\w+\s*=',
    r'alert\s*\(',
    r'document\.cookie',
    r'eval\s*\(',
    r'fromCharCode',
    r'innerHTML|outerHTML',
    r'srcdoc\s*=',
    r'base64',
]

# ── Temporary/disposable email services to block ──
DISPOSABLE_DOMAINS = [
    'temp-mail.org', 'guerrillamail.com', '10minutemail.com',
    'mailinator.com', 'yopmail.com', 'trashmail.com', 'throwaway.email'
]


def validate_full_name(name):
    """Validate full name field with security checks"""
    
    # ── Empty field check ──
    if not name or len(name.strip()) < 1:
        return False, "Full name is required", "Field cannot be empty"
    
    # ── Minimum length requirement ──
    if len(name.strip()) < 2:
        return False, "Full name must be at least 2 characters long", "Minimum length requirement not met"
    
    # ── Block numbers (prevents injection patterns) ──
    if re.search(r'\d', name):
        return False, "Full name cannot contain numbers", "Digits are not allowed in names"
    
    # ── Invalid special characters check ──
    if re.search(r'[^a-zA-Z\s\'\-]', name):
        invalid_chars = set(re.findall(r'[^a-zA-Z\s\'\-]', name))
        return False, "Full name contains invalid special characters", f"Invalid characters found: {', '.join(invalid_chars)}"
    
    # ── Excessive consecutive spaces ──
    if re.search(r'\s{3,}', name):
        return False, "Full name has too many consecutive spaces", "Please use single spaces between words"
    
    return True, "Valid", ""


def validate_email(email):
    """Validate email address with RFC compliance and security checks"""
    
    # ── Empty field check ──
    if not email or not email.strip():
        return False, "Email address is required", "Field cannot be empty"
    
    email = email.strip()
    
    # ── Maximum length check (RFC 5321) ──
    if len(email) > 320:
        return False, "Email address is too long", f"Maximum 320 characters allowed (current: {len(email)})"
    
    # ── Minimum length check ──
    if len(email) < 6:
        return False, "Email address is too short", "Email must be at least 6 characters (e.g., a@b.co)"
    
    # ── Spaces indicate manipulation attempts ──
    if ' ' in email:
        return False, "Email cannot contain spaces", "Whitespace is not allowed in email addresses"
    
    # ── Must contain @ symbol ──
    if '@' not in email:
        return False, "Email must contain '@' symbol", "Missing required @ separator between local and domain parts"
    
    # ── Check for multiple @ symbols ──
    if email.count('@') > 1:
        return False, "Email contains multiple '@' symbols", "Only one @ symbol is allowed"
    
    # ── Split into local and domain parts ──
    try:
        local_part, domain_part = email.rsplit('@', 1)
    except ValueError:
        return False, "Invalid email structure", "Cannot parse local and domain parts"
    
    # ── Validate local part (before @) ──
    if not local_part:
        return False, "Email missing local part", "Nothing found before @ symbol"
    
    if len(local_part) > 64:
        return False, "Email local part is too long", f"Local part max 64 characters (current: {len(local_part)})"
    
    # ── Local part cannot start or end with special characters ──
    if not local_part[0].isalnum():
        return False, "Email cannot start with a special character", f"Local part starts with invalid character: '{local_part[0]}'"
    
    if not local_part[-1].isalnum():
        return False, "Email cannot end with a special character before @", f"Local part ends with invalid character: '{local_part[-1]}'"
    
    # ── Check for consecutive special characters in local part ──
    if re.search(r'\.{2,}', local_part):
        return False, "Email contains consecutive dots", "Multiple consecutive periods are not allowed in local part"
    
    # ── Validate allowed characters in local part ──
    if not re.match(r'^[a-zA-Z0-9._+-]+$', local_part):
        invalid_chars = set(re.findall(r'[^a-zA-Z0-9._+-]', local_part))
        return False, "Email local part contains invalid characters", f"Invalid characters: {', '.join(invalid_chars)}"
    
    # ── Validate domain part (after @) ──
    if not domain_part:
        return False, "Email missing domain part", "Nothing found after @ symbol"
    
    if len(domain_part) > 255:
        return False, "Email domain is too long", f"Domain max 255 characters (current: {len(domain_part)})"
    
    # ── Domain must contain at least one dot ──
    if '.' not in domain_part:
        return False, "Email missing domain extension", "Domain must contain a period (e.g., .com, .org)"
    
    # ── Check for consecutive dots in domain ──
    if '..' in domain_part:
        return False, "Email domain contains consecutive dots", "Consecutive periods are not allowed in domain"
    
    # ── Domain cannot start or end with dot or hyphen ──
    if domain_part[0] in '.-':
        return False, "Email domain starts with invalid character", f"Domain cannot start with '{domain_part[0]}'"
    
    if domain_part[-1] in '.-':
        return False, "Email domain ends with invalid character", f"Domain cannot end with '{domain_part[-1]}'"
    
    # ── Validate TLD (top-level domain) ──
    domain_parts = domain_part.split('.')
    tld = domain_parts[-1]
    
    if len(tld) < 2:
        return False, "Invalid top-level domain", "TLD must be at least 2 characters (e.g., .co, .com)"
    
    if len(tld) > 63:
        return False, "Top-level domain is too long", f"TLD max 63 characters (current: {len(tld)})"
    
    # ── TLD should contain only letters ──
    if not tld.isalpha():
        return False, "Invalid top-level domain format", "TLD should contain only letters"
    
    # ── Validate domain name characters (alphanumeric and hyphens only) ──
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain_part):
        invalid_chars = set(re.findall(r'[^a-zA-Z0-9.-]', domain_part))
        return False, "Email domain contains invalid characters", f"Invalid characters: {', '.join(invalid_chars)}"
    
    # ── Each domain label validation ──
    for label in domain_parts:
        if not label:
            return False, "Email domain has empty label", "Empty section found between dots"
        
        if len(label) > 63:
            return False, "Email domain label is too long", f"Each domain section max 63 characters"
        
        if label[0] == '-' or label[-1] == '-':
            return False, "Email domain label cannot start/end with hyphen", f"Invalid label: '{label}'"
    
    # ── Disposable email detection ──
    domain_lower = domain_part.lower()
    for disposable in DISPOSABLE_DOMAINS:
        if domain_lower.endswith(disposable):
            return False, "Disposable email not allowed", f"Temporary email service detected: {disposable}"
    
    return True, "Valid", ""


def validate_username(username):
    """Validate username with security and format checks"""
    
    # ── Empty field check ──
    if not username or not username.strip():
        return False, "Username is required", "Field cannot be empty"
    
    # ── Check for spaces BEFORE stripping ──
    if ' ' in username:
        return False, "Username cannot contain spaces", "Whitespace is not allowed in usernames"
    
    username = username.strip()
    
    # ── Length constraints ──
    if len(username) < 4:
        return False, "Username must be at least 4 characters long", f"Current length: {len(username)} (minimum: 4)"
    
    if len(username) > 16:
        return False, "Username cannot exceed 16 characters", f"Current length: {len(username)} (maximum: 16)"
    
    # ── Leading numbers can cause SQL issues ──
    if username[0].isdigit():
        return False, "Username cannot start with a number", f"First character '{username[0]}' is a digit"
    
    # ── Check for invalid characters ──
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', username):
        invalid_chars = set(re.findall(r'[^a-zA-Z0-9_]', username))
        if invalid_chars:
            return False, "Username contains invalid characters", f"Invalid characters: {', '.join(invalid_chars)}. Only letters, numbers, and underscores allowed"
        else:
            return False, "Username must start with a letter", "First character must be alphabetic"
    
    # ── Check for consecutive underscores ──
    if '__' in username:
        return False, "Username has consecutive underscores", "Multiple consecutive underscores are not recommended"
    
    return True, "Valid", ""


def validate_message(message):
    """Validate message with XSS and SQL injection detection"""
    
    # ── Empty field check ──
    if not message or not message.strip():
        return False, "Message cannot be empty", "Field is required", []
    
    # ── Length limit ──
    if len(message) > 250:
        return False, "Message cannot exceed 250 characters", f"Current length: {len(message)} (maximum: 250)", []
    
    threats = []
    message_upper = message.upper()
    
    # ── SQL injection detection ──
    sql_found = []
    for keyword in SQL_KEYWORDS:
        if keyword in message_upper:
            sql_found.append(keyword)
    
    if sql_found:
        threats.append(f"SQL keywords detected: {', '.join(sql_found[:3])}")
    
    # ── XSS pattern detection ──
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, message, re.IGNORECASE):
            threats.append("Dangerous HTML/script pattern detected")
            break
    
    # ── Explicit script tag check ──
    if '<script' in message.lower() or '</script>' in message.lower():
        if "script tag" not in str(threats):
            threats.append("Script tag detected (XSS attempt)")
    
    # ── Suspicious image tag check ──
    if '<img' in message.lower() and ('onerror' in message.lower() or 'onclick' in message.lower()):
        threats.append("Suspicious image tag with event handler (XSS attempt)")
    
    # ── Iframe tag check ──
    if '<iframe' in message.lower():
        threats.append("Iframe tag detected (potential embedding attack)")
    
    # ── JavaScript protocol check ──
    if 'javascript:' in message.lower():
        threats.append("JavaScript protocol detected (XSS attempt)")
    
    # ── Admin panel reference check ──
    if re.search(r'\b(admin|login|wp-admin|phpmyadmin)\b', message.lower()):
        threats.append("Admin panel reference detected")
    
    if threats:
        threat_summary = "; ".join(threats)
        return False, "Message contains prohibited content", threat_summary, threats
    
    return True, "Valid", "", []


def sanitize_full_name(name):
    """Remove invalid characters and format name properly"""
    # ── Store original for comparison ──
    original = name
    
    # ── Clean and format the name ──
    name = name.strip()
    name = re.sub(r'\d', '', name)
    name = re.sub(r"[^a-zA-Z\s'\-]", '', name)
    name = re.sub(r'\s+', ' ', name)
    name = name.title()
    
    # ── Check if changes were made ──
    was_sanitized = (original.strip() != name)
    return name, was_sanitized


def sanitize_email(email):
    """Clean and normalize email address"""
    # ── Store original for comparison ──
    original = email
    
    # ── Remove spaces and invalid characters ──
    email = email.replace(' ', '')
    email = re.sub(r'[^a-zA-Z0-9@._+-]', '', email)
    email = re.sub(r'\.{2,}', '.', email)
    email = re.sub(r'_{2,}', '_', email)
    email = re.sub(r'-{2,}', '-', email)
    email = email.lower()
    
    # ── Check if changes were made ──
    was_sanitized = (original != email)
    return email, was_sanitized


def sanitize_username(username):
    """Remove invalid characters and normalize username"""
    # ── Store original for comparison ──
    original = username
    
    # ── Clean and normalize ──
    username = re.sub(r'[^a-zA-Z0-9_]', '', username)
    username = re.sub(r'^[0-9]+', '', username)
    username = username[:16]
    username = username.lower()
    
    # ── Check if changes were made ──
    was_sanitized = (original != username)
    return username, was_sanitized


def sanitize_message(message):
    """Multi-layer sanitization to remove threats"""
    original = message
    notes = []
    
    # ── Layer 1: Remove script tags ──
    if '<script' in message.lower():
        message = re.sub(r'<script[^>]*>.*?</script>', '', message, flags=re.IGNORECASE | re.DOTALL)
        notes.append("Script tags removed")
    
    # ── Layer 2: Remove iframe tags ──
    if '<iframe' in message.lower():
        message = re.sub(r'<iframe[^>]*>.*?</iframe>', '', message, flags=re.IGNORECASE | re.DOTALL)
        notes.append("Iframe tags removed")
    
    # ── Layer 3: Remove dangerous img tags ──
    if '<img' in message.lower() and ('onerror' in message.lower() or 'onclick' in message.lower()):
        message = re.sub(r'<img[^>]*>', '', message, flags=re.IGNORECASE)
        notes.append("Suspicious image tags removed")
    
    # ── Layer 4: Strip event handlers ──
    original_len = len(message)
    message = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', message, flags=re.IGNORECASE)
    if len(message) < original_len:
        notes.append("Event handlers removed")
    
    # ── Layer 5: Remove javascript: protocol ──
    if 'javascript:' in message.lower():
        message = re.sub(r'javascript:', '', message, flags=re.IGNORECASE)
        notes.append("JavaScript protocol removed")
    
    # ── Layer 6: HTML entity escaping ──
    message_escaped = html.escape(message)
    if message != message_escaped:
        message = message_escaped
        notes.append("HTML characters escaped")
    
    # ── Layer 7: SQL keyword filtering ──
    for keyword in SQL_KEYWORDS:
        if keyword in message.upper():
            message = re.sub(keyword, '[FILTERED]', message, flags=re.IGNORECASE)
            if "SQL keywords filtered" not in notes:
                notes.append("SQL keywords filtered")
    
    # ── Layer 8: Remove SQL comment patterns ──
    if '--' in message or '/*' in message:
        message = message.replace('--', '').replace('/*', '').replace('*/', '')
        notes.append("SQL comment patterns removed")
    
    # ── Layer 9: Enforce length limit ──
    if len(message) > 250:
        message = message[:250]
        notes.append("Message truncated to 250 characters")
    
    return message, notes


def validate_and_sanitize_form(form_data):
    """Main validation function for all form fields"""
    # ── Initialize results structure ──
    results = {
        'validation': {},
        'sanitized': {},
        'errors': [],
        'summary': [],
        'all_valid': True,
        'has_empty_fields': False
    }
    
    # ── Check for empty required fields ──
    required_fields = ['full_name', 'email', 'username', 'message']
    empty_fields = []
    
    for field in required_fields:
        if not form_data.get(field, '').strip():
            empty_fields.append(field.replace('_', ' ').title())
    
    # ── Return early if any required fields are empty ──
    if empty_fields:
        results['has_empty_fields'] = True
        results['empty_fields'] = empty_fields
        results['all_valid'] = False
        return results
    
    # ── Validate and sanitize Full Name ──
    name_valid, name_msg, name_details = validate_full_name(form_data.get('full_name', ''))
    sanitized_name, name_sanitized = sanitize_full_name(form_data.get('full_name', ''))
    
    # ── Store full name results ──
    results['validation']['full_name'] = {
        'valid': name_valid,
        'message': name_msg,
        'details': name_details,
        'sanitized': name_sanitized
    }
    results['sanitized']['full_name'] = sanitized_name
    
    # ── Add errors or sanitization notes for full name ──
    if not name_valid:
        results['all_valid'] = False
        results['errors'].append(f"Full Name: {name_msg}")
        if name_details:
            results['errors'].append(f"  → {name_details}")
        results['summary'].append(f"Full Name: {name_msg}")
    elif name_sanitized:
        results['summary'].append("Full Name: Sanitized (invalid characters removed and formatted)")
    
    # ── Validate and sanitize Email ──
    email_valid, email_msg, email_details = validate_email(form_data.get('email', ''))
    sanitized_email, email_sanitized = sanitize_email(form_data.get('email', ''))
    
    # ── Store email results ──
    results['validation']['email'] = {
        'valid': email_valid,
        'message': email_msg,
        'details': email_details,
        'sanitized': email_sanitized
    }
    results['sanitized']['email'] = sanitized_email
    
    # ── Add errors or sanitization notes for email ──
    if not email_valid:
        results['all_valid'] = False
        results['errors'].append(f"Email: {email_msg}")
        if email_details:
            results['errors'].append(f"  → {email_details}")
        results['summary'].append(f"Email: {email_msg}")
    elif email_sanitized:
        results['summary'].append("Email: Sanitized (spaces/invalid characters removed, converted to lowercase)")
    
    # ── Validate and sanitize Username ──
    user_valid, user_msg, user_details = validate_username(form_data.get('username', ''))
    sanitized_user, user_sanitized = sanitize_username(form_data.get('username', ''))
    
    # ── Store username results ──
    results['validation']['username'] = {
        'valid': user_valid,
        'message': user_msg,
        'details': user_details,
        'sanitized': user_sanitized
    }
    results['sanitized']['username'] = sanitized_user
    
    # ── Add errors or sanitization notes for username ──
    if not user_valid:
        results['all_valid'] = False
        results['errors'].append(f"Username: {user_msg}")
        if user_details:
            results['errors'].append(f"  → {user_details}")
        results['summary'].append(f"Username: {user_msg}")
    elif user_sanitized:
        results['summary'].append("Username: Sanitized (invalid characters removed, converted to lowercase)")
    
    # ── Validate and sanitize Message ──
    msg_valid, msg_msg, msg_details, threats = validate_message(form_data.get('message', ''))
    sanitized_msg, msg_notes = sanitize_message(form_data.get('message', ''))
    
    # ── Store message results ──
    results['validation']['message'] = {
        'valid': msg_valid,
        'message': msg_msg,
        'details': msg_details,
        'threats': threats,
        'sanitized': len(msg_notes) > 0
    }
    results['sanitized']['message'] = sanitized_msg
    results['sanitization_notes'] = msg_notes
    
    # ── Add errors or sanitization notes for message ──
    if not msg_valid:
        results['all_valid'] = False
        results['errors'].append(f"Message: {msg_msg}")
        if msg_details:
            results['errors'].append(f"  → {msg_details}")
        results['summary'].append(f"Message: {msg_msg}")
    elif msg_notes:
        results['summary'].append(f"Message: Sanitized ({', '.join(msg_notes)})")
    
    return results