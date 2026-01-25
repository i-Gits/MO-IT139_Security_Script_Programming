# Documentation

### load_dictionary()
Location: src/utils/dictionary.py

Purpose: Loads a local dictionary file (dictionary.txt) into a Python list used to detect words inside passwords.
Returns list of words (lowercase) with length >= 4.
Prints debug messages and returns a small fallback list when dictionary.txt is missing.

### load_nltk_words(min_len=4, max_len=None)
Location: src/utils/dictionary.py

Purpose: Loads words from the NLTK corpus (if installed) and returns them filtered by length.
NLTK import is guarded with try/except block - returns [] if NLTK is not installed (NO CRASH).
Safe to use - app works fine without NLTK using local dictionary only.

### generate_password(length)
Location: src/features/password_generator.py

Purpose: Generates random password with required character types.
Guarantees: 1 uppercase, 1 lowercase, 1 digit, 1 special char.
Shuffles to prevent patterns.
Returns string password of specified length (8-16).

### hash_password(password)
Location: src/features/password_generator.py

Purpose: Creates SHA-256 hash with random salt.
Returns tuple: (salt_hex, hashed)
Salt is 16 bytes random, converted to hex for storage.
Used for secure password verification later.

### save_to_file(salt, hashed, timestamp)
Location: src/features/password_generator.py

Purpose: Saves ONLY salt and hash to passwords.txt (password NOT saved for security).
Uses append mode to keep previous entries.
Returns True if successful, False on error.

### load_password_entries()
Location: src/features/password_generator.py

Purpose: Loads all password entries from file.
Returns list of dictionaries containing: timestamp, salt, hash.
Returns empty list if file doesn't exist or on error.

### verify_password_hash(password, entries)
Location: src/features/password_generator.py

Purpose: Verifies entered password against saved hashes using salt.
Loops through entries, reconstructs hash with saved salt, compares.
Returns timestamp string if match found, None if no match.

### evaluate_password_strength(password)
Location: src/features/password_strength.py

Purpose: Main password assessor - tests password strength and provides feedback.
Returns tuple: (rating, color, feedback_messages)
 - rating: "WEAK", "MODERATE", or "STRONG"
 - color: hex color code (#ef4444, #f59e0b, #22c55e)
 - feedback_messages: list of strings

Runs 5 structural checks (length, uppercase, lowercase, digits, symbols).
Runs 2 veto checks (common passwords, dictionary words).
Score totals up to 7; rating based on final score:
 - Weak if common or contains dictionary word OR score <= 4
 - Moderate if score 5-6
 - Strong otherwise

### validate_full_name(name)
Location: src/features/form_validator.py

Purpose: Validates full name for web forms.
Rules: min 2 chars, no numbers, only letters/spaces/hyphens/apostrophes.
Returns (is_valid, error_message, details).

### validate_email(email)
Location: src/features/form_validator.py

Purpose: Validates email address with RFC standards.
Rules: must contain @, valid domain, no spaces, proper format, max 320 chars.
Returns (is_valid, error_message, details).

### validate_username(username)
Location: src/features/form_validator.py

Purpose: Validates username with character restrictions.
Rules: 4-16 chars, alphanumeric + underscore only, cannot start with number.
Returns (is_valid, error_message, details).

### validate_message(message)
Location: src/features/form_validator.py

Purpose: Validates message/comment with threat detection.
Rules: not empty, max 250 chars, detects XSS/SQL injection patterns.
Detects: script tags, SQL keywords, event handlers, dangerous HTML.
Returns (is_valid, error_message, details, detected_threats).

### sanitize_full_name(name)
Location: src/features/form_validator.py

Purpose: Removes invalid characters from full name, converts to Title Case.
Returns (sanitized_name, was_sanitized).

### sanitize_email(email)
Location: src/features/form_validator.py

Purpose: Removes spaces and dangerous characters, converts to lowercase.
Returns (sanitized_email, was_sanitized).

### sanitize_username(username)
Location: src/features/form_validator.py

Purpose: Removes invalid characters, leading numbers, limits to 16 chars, converts to lowercase.
Returns (sanitized_username, was_sanitized).

### sanitize_message(message)
Location: src/features/form_validator.py

Purpose: Multi-layer security sanitization (9 layers).
Operations: removes script/iframe tags, strips event handlers, escapes HTML, filters SQL keywords.
Returns (sanitized_message, sanitization_notes).

### validate_and_sanitize_form(form_data)
Location: src/features/form_validator.py

Purpose: Main function to validate and sanitize all form fields.
Takes dict with keys: full_name, email, username, message.
Returns dict with validation results, sanitized data, errors, summary.


## GUI Components

### MainMenu
Location: src/gui/main_menu.py

Purpose: Main menu window with navigation to all tools.
Three large buttons with cyan hover effects (#38bdf8):
 - "CHECK PASSWORD STRENGTH"
 - "GENERATE RANDOM PASSWORD"
 - "VALIDATE WEB FORM INPUT"
Hides itself when tool window opens, shows again on back button.

### PasswordStrengthWindow
Location: src/gui/password_strength_tab.py

Purpose: Password strength analyzer window.
Features: single password input, analyze button, Enter key binding, color-coded verdict (WEAK/MODERATE/STRONG), visual strength bar, detailed feedback with bullet points.

### PasswordGeneratorWindow
Location: src/gui/password_generator_tab.py

Purpose: Password generator window with hashing and verification.
Features: length dropdown (8-16), generate button, display area (shows password and hash with warning), clear display button, verify password button (opens modal), back to menu button.
**Security**: Raw passwords NOT saved to file - only hash and salt stored.

### FormValidatorWindow
Location: src/gui/form_validator_tab.py

Purpose: Web form input validator and sanitizer window.
Features: input fields (name, email, username, message), validate & sanitize button, clear form button, scrollable results popup with color-coded status, validation results per field, sanitized output, sanitization summary, threat detection alerts (XSS, SQL injection).


## Version History

### Version 3.1 (Current - Complete Security Toolkit)

Tools:
1. Password Strength Analyzer
2. Secure Password Generator
3. Web Form Validator & Sanitizer

Key Features:
- Unified application with main menu navigation
- Cyan hover effects on buttons (#38bdf8)
- Modular code structure (src/gui/, src/features/, src/utils/)
- Dark blue theme across all windows
- NLTK safety (guarded import prevents crashes)
- **Password generator security**: Raw passwords NOT saved to file, only hash/salt stored with warning popup
- **XSS/SQL injection prevention**: Multi-layer sanitization for web form inputs
- Real-time threat detection and detailed error messages

File structure:
 - src/main.py (entry point)
 - src/gui/ (main_menu, password_strength_tab, password_generator_tab, form_validator_tab)
 - src/features/ (password_strength, password_generator, form_validator)
 - src/utils/ (dictionary)

Security notes:
- Password veto logic catches poor passwords with real words
- Dictionary-based checks (local + optional NLTK)
- SHA-256 hashing with random salt
- Pattern-based threat identification (regex for XSS/SQL)
- HTML entity escaping for safe output
- Character-type enforcement per field

Previously: Two tools (password strength + generator)
Current: Three tools (password strength + generator + webform validator)