# MO-IT139_Security_Script_Programming
Security Script Programming 2026


# PASSECURIST | PASSWORD SECURITY TOOLKIT

Features
1. Password Strength Analyzer (PASSECURIST)

- Analyzes password strength based on multiple criteria
- Checks structure (length, uppercase, lowercase, numbers, symbols)
- Detects common passwords
- Identifies dictionary words in passwords
- Uses local dictionary file and optional NLTK words corpus
- Color-coded strength ratings (Weak/Moderate/Strong)

Password Strength Criteria
Structural Checks (5 points)

✓ Length >= 12 characters
✓ Contains uppercase letter
✓ Contains lowercase letter
✓ Contains digit
✓ Contains special character

Veto Checks (2 points)

✓ Not a common password
✓ Contains no dictionary words

Scoring System

Maximum score: 7 points (5 structural + 2 veto)
STRONG: 7 points (all checks passed)
MODERATE: 5-6 points
WEAK: ≤4 points OR any veto triggered


2. Secure Password Generator

- Generates random passwords (8-16 characters)
- Guarantees character diversity (uppercase, lowercase, digits, special chars)
- SHA-256 hashing with random salt
- Saves generated passwords to file
- Password verification feature
- Secure display with clear function

Generated Password File Format
Passwords are saved to passwords.txt in this format:

Timestamp: 2026-01-18 14:30:45
Password: aB3$xYz9KlMn
Salt: 3f7a2b1c9d8e5f4a3b2c1d0e9f8a7b6c
Hash: 5d41402abc4b2a76b9719d911017c592...
--------------------------------------------------

How to run:
1. (Optional) Install NLTK and download words corpus if you want larger dictionary checks:
   - python -m pip install nltk
   - python -m nltk.downloader words
2. Run app:
   - python src/main.py
3. Choose a tool from the main menu (buttons with hover effects)
4. Use "BACK TO MENU" button to navigate between tools

Key files:
- src/main.py
    > application entry point, launches main menu
- src/gui/main_menu.py
    > main menu with navigation to password tools
- src/features/password_strength.py
    > password strength evaluation logic
- src/features/password_generator.py
    > password generation, hashing, and verification logic
- src/utils/dictionary.py
    > dictionary loading utilities for word detection
- data/dictionary.txt
    > optional local word list (fallback list used if not found)
