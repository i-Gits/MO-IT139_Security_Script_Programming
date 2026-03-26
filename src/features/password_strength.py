# src/features/password_strength.py
import re
import string
from utils.dictionary import DICTIONARY_WORDS

# Common passwords that immediately flag as weak
COMMON_PASSWORDS = {
    "password", "123456", "qwerty", "admin", "letmein",
    "welcome", "login", "12345", "iloveyou"
}

# Color codes for rating levels
COLOR_WEAK = "#ef4444"
COLOR_MOD = "#f59e0b"
COLOR_STRONG = "#22c55e"

def evaluate_password_strength(password):
    """
    Evaluate password strength based on structural and veto checks.
    Returns: (rating, color, feedback_messages)
    """
    if not password:
        return "WEAK", COLOR_WEAK, ["Please enter a password before checking."]
    
    score = 0
    feedback = []
    passed_feedback = []
    
    # Structural checks (5 total)
    # Used safe membership check for special characters instead of regex which can crash on punctuation metacharacters
    special_char = any(ch in string.punctuation for ch in password)
    
    checks = [
        (len(password) >= 12, "Length < 12", "✅ Length >= 12 "),
        (re.search(r"[A-Z]", password), "No uppercase letter", "✅ Contains uppercase letter "),
        (re.search(r"[a-z]", password), "No lowercase letter", "✅ Contains lowercase letter "),
        (re.search(r"[0-9]", password), "No number", "✅ Contains number "),
        (special_char, "No special character", "✅ Contains special character ")
    ]
    
    for passed, fail_msg, success_msg in checks:
        if passed:
            score += 1
            passed_feedback.append(success_msg)
        else:
            feedback.append(fail_msg)
    
    # Veto checks
    is_common = password.lower() in COMMON_PASSWORDS
    has_dictionary_word = False
    found_word = ""
    
    pwd_lower = password.lower()
    for word in DICTIONARY_WORDS:
        if word in pwd_lower:
            has_dictionary_word = True
            found_word = word
            break
    
    if is_common:
        feedback.insert(0, "⚠ Common password detected. Don't get lazy!")
    else:
        passed_feedback.append("✅ Not a common password")
        score += 1
        
    if has_dictionary_word:
        feedback.insert(0, f"Contains dictionary word: '{found_word}'")
    else:
        passed_feedback.append("✅ No dictionary words found ")
        score += 1
    
    
    # Final rating (max score = 7)
    if is_common or has_dictionary_word:
        return "WEAK", COLOR_WEAK, feedback + passed_feedback
    
    if score <= 4:
        return "WEAK", COLOR_WEAK, feedback + passed_feedback
    elif score <= 6:
        return "MODERATE", COLOR_MOD, feedback + passed_feedback
    else:
        return "STRONG", COLOR_STRONG, ["Excellent!"] + passed_feedback