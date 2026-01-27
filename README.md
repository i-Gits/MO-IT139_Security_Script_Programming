# MO-IT142 Draft of Milestone 1: Web Security Tool BSIT -S31101 Delas Armas, J., Encillo, C., Samaniego, M., Tantoco, H.
Security Script Programming 2026

## PASSECURIST

A comprehensive security toolkit with four main features:
1. **Password Strength Analyzer** - Evaluates password security with structural and dictionary checks
2. **Password Generator & Hasher** - Creates strong passwords and generates SHA-256 hashes
3. **Web Form Validator & Sanitizer** - Validates and sanitizes form inputs against XSS/SQL injection

---

## Features Overview

### 1. Password Strength Analyzer
- Analyzes password structure (length, uppercase, lowercase, numbers, symbols)
- Flags common passwords and dictionary words immediately
- Uses local dictionary file and optional NLTK corpus
- Visual strength indicator (Weak/Moderate/Strong)
- Generates SHA-256 hash of entered password

### 2. Password Generator
- Generates cryptographically secure passwords (8-16 characters)
- Automatically includes all character types
- Creates SHA-256 hash with random salt
- Copy functions for password, hash, and code blocks
- **Security**: Raw passwords are NEVER saved to disk

### 3. Web Form Validator
- Validates 4 fields: Full Name, Email, Username, Message
- Checks for SQL injection keywords and XSS patterns
- Email validation follows RFC 5321 standards
- Blocks disposable email domains
- Shows ALL violations per field with inline feedback
- Displays sanitized output for safe database storage

---

## How to Run

### Installation
```bash
# Optional: Install NLTK for extended dictionary
python -m pip install nltk
python -m nltk.downloader words

# Required for encryption feature
python -m pip install cryptography
```

### Launch Application
```bash
python main.py
```

---

## Key Files

### Core Application
- **main.py** - Main application entry point with tabbed interface
- **dictionary.txt** - Local word list for password strength checking (optional)

### Features (`src/features/`)
- **password_strength.py** - Password evaluation logic with veto checks
- **password_generator.py** - Secure password generation and hashing
- **webform_validator.py** - Form validation with XSS/SQL injection detection

### Utilities (`src/utils/`)
- **dictionary.py** - Dictionary loading (local + NLTK)
- **genPassStorage.py** - Password hash storage (NO raw passwords)

### GUI (`gui/`)
- **password_strength_tab.py** - Strength analyzer interface
- **password_generator_tab.py** - Generator interface
- **web_validator_tab.py** - Form validator interface
- **styles.py** - Application theme configuration

---

## Password Strength Evaluation

### Structural Checks (5 points)
1. Length ≥ 12 characters
2. Contains uppercase letter
3. Contains lowercase letter
4. Contains number
5. Contains special character

### Veto Checks (2 bonus points)
1. Not in common passwords list
2. Contains no dictionary words

**Scoring:**
- **Strong**: Score = 7 (all checks passed, no veto)
- **Moderate**: Score = 5-6
- **Weak**: Score ≤ 4 OR vetoed by common password/dictionary word

---

## Web Form Validation Rules

### Full Name
- Minimum 2 characters
- No numbers allowed
- Only letters, spaces, hyphens, apostrophes
- Allows single-space format only (✅"Mario Juan" | ❌"Mario  Juan")

### Email
- RFC 5321 compliant (max 320 chars)
- Valid structure: local@domain.tld
- No spaces, consecutive dots, or invalid characters
- Should not start with a special character
- Blocks disposable email domains

### Username
- 4-16 characters
- Must start with letter
- No spaces allowed
- Only letters, numbers, underscores
- No consecutive underscores

### Message
- Max 250 characters
- Should not be empty
- Blocks SQL keywords (SELECT, DROP, etc.)
- Blocks XSS patterns (script tags, event handlers)
- Blocks JavaScript protocols

---

## Security Features

### Password Generator
- ✓ Cryptographically secure random generation
- ✓ SHA-256 hashing with 16-byte random salt
- ✓ Raw passwords NEVER saved to disk
- ✓ Hash storage in `data/passwords.txt`
- ✓ Copy functions for easy password management

### Password Strength Analyzer
- ✓ Dictionary word detection (local + NLTK)
- ✓ Common password veto system
- ✓ Visual strength indicators
- ✓ SHA-256 hash generation for analysis
- ✓ Detailed feedback on weaknesses

### Web Form Validator
- ✓ Multi-layer sanitization (9 layers)
- ✓ SQL injection keyword filtering
- ✓ XSS pattern detection and removal
- ✓ HTML entity escaping
- ✓ Inline validation with ALL violations shown


---

## Data Storage

### Generated Passwords (`data/passwords.txt`)
Format: `[timestamp] | hash # salt`
- Stores hash and salt only
- NO raw passwords saved
- Append mode (previous entries preserved)

---

## Dependencies
```
tkinter (built-in)
hashlib (built-in)
os (built-in)
re (built-in)
html (built-in)
string (built-in)
random (built-in)
datetime (built-in)
nltk (optional - for extended dictionary)
```

---

## Version History

### MS1 (Draft) 
**Core Features Implemented - January 26, 2026**:
- Password Strength Analyzer with 7-point scoring system
- Password Generator & Hasher with SHA-256
- Web Form Validator & Sanitizer with XSS/SQL injection protection

**Bug Fixes Applied - January 27, 2026**:
- Fixed duplicate space error in username validation (spaces excluded from invalid chars regex)
- Improved error message display (quoted special characters)
- Strict single-space formatting for full names (`\s{2,}`)

### MS1 (Final)
*In progress - awaiting final review and testing*

---

## Notes

- **NLTK is optional**: App works without it but has smaller dictionary
- **Raw passwords**: NEVER stored in password generator
---

## Group's Project Plan
- Link: https://docs.google.com/spreadsheets/d/1oXL5hJg6MRoZwp_r84P0JkorvVMnKP5bkcYPTfBOUP0/edit?usp=sharing
