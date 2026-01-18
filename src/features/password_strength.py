# Password strength evaluation 

import re
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
    
    Args:
        password: The password string to evaluate
    
    Returns:
        tuple: (rating, color, feedback_messages)
            - rating: "WEAK", "MODERATE", or "STRONG"
            - color: hex color code for display
            - feedback_messages: list of feedback strings
    """
    if not password:
        return "WEAK", COLOR_WEAK, ["Please enter a password before checking."]
    
    score = 0
    feedback = []
    
    # Structural checks (5 total)
    checks = [
        (len(password) >= 12, "Length < 12"),
        (re.search(r"[A-Z]", password), "No uppercase letter"),
        (re.search(r"[a-z]", password), "No lowercase letter"),
        (re.search(r"[0-9]", password), "No number"),
        (re.search(r'[!@#$%^&*()_+\-=\[\]{};:\"\',.<>/?\\|]', password), "No special character")
    ]
    
    for passed, msg in checks:
        if passed:
            score += 1
        else:
            feedback.append(msg)
    
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
    if has_dictionary_word:
        feedback.insert(0, f"Contains dictionary word: '{found_word}'")
    
    # Bonus points for not being vetoed
    if not is_common:
        score += 1
    if not has_dictionary_word:
        score += 1
    
    # Final rating (max score = 7)
    if is_common or has_dictionary_word:
        return "WEAK", COLOR_WEAK, feedback
    
    if score <= 4:
        return "WEAK", COLOR_WEAK, feedback
    elif score <= 6:
        return "MODERATE", COLOR_MOD, feedback
    else:
        return "STRONG", COLOR_STRONG, ["Excellent password structure! Keep it up."] if not feedback else feedback