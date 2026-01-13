import re
from utils.dictionary import DICTIONARY_WORDS

COMMON_PASSWORDS = {
    "password", "123456", "qwerty", "admin", "letmein",
    "welcome", "login", "12345", "iloveyou"
}

def evaluate_password_strength(password: str) -> tuple[str, str, list[str]]:
    """
    Returns:
        (rating, color_name, feedback_messages)
    """
    if not password:
        return "WEAK", "red", ["Please enter a password"]

    score = 0
    feedback = []

    # Structural checks
    checks = [
        (len(password) >= 12,           "Length < 12"),
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
        feedback.insert(0, "Common password detected")
    if has_dictionary_word:
        feedback.insert(0, f"Contains dictionary word: '{found_word}'")

    # Bonus points for not being vetoed
    if not is_common:
        score += 1
    if not has_dictionary_word:
        score += 1

    # Final rating
    if is_common or has_dictionary_word:
        return "WEAK", "red", feedback

    if score <= 4:
        return "WEAK", "red", feedback
    if score <= 6:
        return "MODERATE", "orange", feedback
    else:
        return "STRONG", "green", ["Looks good!"] if not feedback else feedback