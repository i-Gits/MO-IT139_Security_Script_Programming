# src/utils/security_logger.py
import os
from datetime import datetime

# Define log file path
LOG_DIR = os.path.join(os.getcwd(), "data")
LOG_FILE = os.path.join(LOG_DIR, "security_log.txt")


def ensure_log_dir():
    """Create data directory if it doesn't exist"""
    os.makedirs(LOG_DIR, exist_ok=True)


def log_threat(field_name, threat_type, original_value, sanitized_value, detected_patterns):
    """
    Log security threats (XSS, SQL injection, etc.)
    
    Args:
        field_name: Name of the field (e.g., "Message", "Email")
        threat_type: Type of threat (e.g., "XSS ATTEMPT", "SQL INJECTION")
        original_value: Original user input
        sanitized_value: Cleaned/sanitized value
        detected_patterns: List of detected malicious patterns
    """
    try:
        ensure_log_dir()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_entry = f"\n{'='*70}\n"
        log_entry += f"[{timestamp}] ⚠ {threat_type}\n"
        log_entry += f"  Field: {field_name}\n"
        log_entry += f"  Detected: {', '.join(detected_patterns)}\n"
        log_entry += f"  Original: {original_value[:100]}{'...' if len(original_value) > 100 else ''}\n"
        log_entry += f"  Sanitized: {sanitized_value[:100]}{'...' if len(sanitized_value) > 100 else ''}\n"
        log_entry += f"{'='*70}\n"
        
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
        
        return True
    except Exception as e:
        print(f"Error writing to security log: {e}")
        return False


def log_sanitization(field_name, original_value, sanitized_value, reason):
    """
    Log field sanitization (removing invalid characters, formatting, etc.)
    
    Args:
        field_name: Name of the field
        original_value: Original user input
        sanitized_value: Cleaned value
        reason: Description of what was sanitized
    """
    try:
        ensure_log_dir()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_entry = f"[{timestamp}] SANITIZATION - {field_name}\n"
        log_entry += f"  Original: {original_value}\n"
        log_entry += f"  Sanitized: {sanitized_value}\n"
        log_entry += f"  Reason: {reason}\n\n"
        
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
        
        return True
    except Exception as e:
        print(f"Error writing to security log: {e}")
        return False


def log_validation_summary(form_data, results):
    """
    Log complete validation summary for a form submission
    
    Args:
        form_data: Original form data dictionary
        results: Validation results from validate_and_sanitize_form()
    """
    try:
        ensure_log_dir()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_entry = f"\n{'*'*70}\n"
        log_entry += f"[{timestamp}] FORM VALIDATION SUMMARY\n"
        log_entry += f"{'*'*70}\n"
        
        # Log each field status
        fields = ['full_name', 'email', 'username', 'message']
        for field in fields:
            field_label = field.replace('_', ' ').title()
            validation = results['validation'].get(field, {})
            
            if validation.get('valid'):
                if validation.get('sanitized'):
                    log_entry += f"  ⚠ {field_label}: Valid (sanitized)\n"
                else:
                    log_entry += f"  ✓ {field_label}: Valid\n"
            else:
                log_entry += f"  ✗ {field_label}: Invalid - {validation.get('message', 'Unknown error')}\n"
        
        # Overall status
        log_entry += f"\n  Overall Status: {'PASSED' if results['all_valid'] else 'FAILED'}\n"
        
        # Sanitization summary
        if results.get('summary'):
            log_entry += f"\n  Sanitization Actions:\n"
            for action in results['summary']:
                log_entry += f"    - {action}\n"
        
        log_entry += f"{'*'*70}\n\n"
        
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
        
        return True
    except Exception as e:
        print(f"Error writing to security log: {e}")
        return False


def log_attack_attempt(field_name, attack_type, original_value):
    """
    Log serious attack attempts (SQL injection, XSS, etc.)
    
    Args:
        field_name: Name of the field
        attack_type: Type of attack detected
        original_value: Malicious input attempted
    """
    try:
        ensure_log_dir()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_entry = f"\n{'!'*70}\n"
        log_entry += f"[{timestamp}] !!! ATTACK ATTEMPT DETECTED !!! \n"
        log_entry += f"  Field: {field_name}\n"
        log_entry += f"  Attack Type: {attack_type}\n"
        log_entry += f"  Malicious Input: {original_value[:150]}{'...' if len(original_value) > 150 else ''}\n"
        log_entry += f"{'!'*70}\n\n"
        
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
        
        return True
    except Exception as e:
        print(f"Error writing to security log: {e}")
        return False