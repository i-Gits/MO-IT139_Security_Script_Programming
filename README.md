# MO-IT139_Security_Script_Programming
Security Script Programming 2026


# PASSECURIST | PASSWORD SECURITY TOOLKIT

A comprehensive security toolkit with three core tools: Password Strength Analyzer, Secure Password Generator, and Web Form Input Validator.


## Features

### 1. Password Strength Analyzer (PASSECURIST)

- Analyzes password strength based on multiple criteria
- Checks structure (length, uppercase, lowercase, numbers, symbols)
- Detects common passwords
- Identifies dictionary words in passwords
- Uses local dictionary file and optional NLTK words corpus
- Color-coded strength ratings with visual bar (Weak/Moderate/Strong)

**Scoring System:**
- **Structural Checks (5 points):** Length ≥12, uppercase, lowercase, digit, special character
- **Veto Checks (2 points):** Not common password, no dictionary words
- **Maximum score:** 7 points
- **STRONG:** 7 points | **MODERATE:** 5-6 points | **WEAK:** ≤4 points OR veto triggered


### 2. Secure Password Generator

- Generates random passwords (8-16 characters)
- Guarantees character diversity (uppercase, lowercase, digits, special chars)
- SHA-256 hashing with random salt
- **Security:** Raw passwords NOT saved to file - only hash and salt stored
- Warning popup to copy password before closing
- Password verification feature against saved hashes
- Secure display with clear function

**Generated Password File Format (passwords.txt):**
```
Timestamp: 2026-01-25 14:30:45
Salt: 3f7a2b1c9d8e5f4a3b2c1d0e9f8a7b6c
Hash: 5d41402abc4b2a76b9719d911017c592...
--------------------------------------------------
```


### 3. Web Form Input Validator & Sanitizer

**Form Fields:**
- **Full Name:** min 2 chars, letters/spaces/hyphens/apostrophes only
- **Email Address:** must have @, valid domain, RFC standards, max 320 chars
- **Username:** 4-16 chars, alphanumeric + underscore, cannot start with number
- **Message/Comment:** max 250 chars, threat detection enabled

**Security Features:**
- **XSS Prevention:** Removes `<script>`, `<iframe>`, dangerous event handlers
- **SQL Injection Detection:** Filters keywords (SELECT, DROP, INSERT, DELETE, etc.)
- **HTML Sanitization:** Escapes special characters (`<`, `>`, `&`)
- **Pattern-Based Threats:** Detects `javascript:` protocol, suspicious `<img>` tags
- **Multi-Layer Sanitization:** 9 security layers applied to message field
- **Real-Time Feedback:** Color-coded validation results (✓ Valid / ✗ Invalid)

**Output Sections:**
1. **Validation Results** - Shows which fields pass/fail with specific error messages
2. **Sanitized Output** - Displays cleaned versions of all inputs
3. **Sanitization Summary** - Lists what was removed/filtered and why

**Example Test Inputs:**
```
Full Name: J0hn D0e              → Invalid (contains numbers)
Email: john doe@gmail.com        → Invalid (contains spaces)
Username: 123user                → Invalid (starts with number)
Message: <script>alert('XSS')</script>  → ⚠ Threat detected & sanitized
```


## How to Run

1. **(Optional)** Install NLTK for larger dictionary checks:
```bash
   python -m pip install nltk
   python -m nltk.downloader words
```

2. **Run application:**
```bash
   python src/main.py
```

3. **Navigate:**
   - Choose a tool from the main menu (buttons with cyan hover effects)
   - Use "BACK TO MENU" button to switch between tools


## Version

**Version 3.1** - Complete Security Toolkit (Current)
- Three integrated tools with unified dark blue theme
- Enhanced security: passwords not saved in plain text
- Real-time threat detection for web forms
- Detailed error messages and sanitization reports