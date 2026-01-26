# Documentation

## Password Strength Analyzer

### load_dictionary()
**Purpose**: Loads a local dictionary file (dictionary.txt) into a Python list used to detect words inside passwords.

**Parameters**: None

**Returns**: List of words (lowercase) with length >= 4

**Details**: 
- Reads dictionary.txt from the data folder
- Filters words to keep only those with 4+ characters
- Prints debug messages and returns a small fallback list when dictionary.txt is missing
- Fallback words: ["apple", "computer", "dragon", "monkey", "secret"]

---

### load_nltk_words(min_len=4, max_len=None)
**Purpose**: Loads words from the NLTK corpus (if installed) and returns them filtered by length.

**Parameters**:
- `min_len` (int, default=4): Minimum word length
- `max_len` (int or None): Maximum word length (None = no limit)

**Returns**: List of corpus words in lowercase meeting length rules

**Notes**:
- Returns empty list [] if NLTK is not installed or corpus is missing
- Does not automatically download corpus
- Current implementation: `nltk` is imported at the top (unguarded)
  - **Warning**: Code will crash if nltk is not installed
  - Future improvement: Guard the import for better error handling

---

### evaluate_password_strength(password)
**Purpose**: Main password assessment function that tests password strength and provides detailed feedback.

**Parameters**:
- `password` (str): The password to evaluate

**Returns**: Tuple of (rating, color, messages)
- `rating` (str): "WEAK", "MODERATE", or "STRONG"
- `color` (str): Hex color code for UI display
- `messages` (list): List of feedback strings

**Evaluation Logic**:

#### Structural Checks (5 points)
1. Length >= 12 characters
2. Contains uppercase letter
3. Contains lowercase letter
4. Contains digits
5. Contains special characters (punctuation)

#### Veto Checks (2 bonus points)
1. Not in COMMON_PASSWORDS list (exact match, case-insensitive)
2. Does not contain any DICTIONARY_WORDS (case-insensitive substring check)

**Scoring System**:
- Maximum score: 7 points (5 structural + 2 veto bonuses)
- **STRONG**: No veto triggers AND score = 7
- **MODERATE**: No veto triggers AND score = 5-6
- **WEAK**: Veto triggered OR score <= 4

**Special Behaviors**:
- Veto checks override structural score (common password or dictionary word = automatic WEAK)
- Detected dictionary words are printed to terminal for debugging
- Case-insensitive matching for both common passwords and dictionary words
- Returns early with warning if input is empty

**Where Used**: 
- Button command in GUI
- Enter key binding for quick analysis

---

### show_custom_warning(title, message)
**Purpose**: Display a custom-themed modal warning window.

**Parameters**:
- `title` (str): Window title
- `message` (str): Warning message to display

**Returns**: None (displays popup)

**Details**:
- Creates a blocking popup using the app's dark blue theme
- Matches main application styling
- Called when user submits empty input in evaluate_password_strength()

---

## Password Generator & Hasher

### generate_password(length=12)
**Purpose**: Generate a cryptographically secure password.

**Parameters**:
- `length` (int, default=12): Desired password length (clamped to 8-16)

**Returns**: String containing generated password

**Details**:
- Ensures at least one character from each class: uppercase, lowercase, digit, punctuation
- Remaining characters randomly selected from all classes
- Final password is shuffled for randomness
- Length automatically adjusted if below 8 or above 16

---

### hash_password(password)
**Purpose**: Hash a password using SHA-256 with random salt.

**Parameters**:
- `password` (str): Password to hash

**Returns**: Tuple of (salt_hex, hash_hex)
- `salt_hex` (str): 16-byte salt as hex string
- `hash_hex` (str): SHA-256 hash as hex string

**Details**:
- Generates 16-byte random salt using os.urandom()
- Prepends salt to password before hashing
- Returns both salt and hash (both needed for verification)

---

### save_to_file(salt_hex, hash_hex, timestamp, password=None)
**Purpose**: Save hash entry to file (password parameter is NOT saved).

**Parameters**:
- `salt_hex` (str): Salt in hexadecimal
- `hash_hex` (str): Hash in hexadecimal
- `timestamp` (str): Timestamp string
- `password` (str, optional): NOT SAVED - only used for validation

**Returns**: Boolean (True if saved successfully)

**File Format**: `[timestamp] | hash # salt`

**Security**: Raw password is NEVER written to disk, only hash and salt are stored.

---

## Web Form Validator & Sanitizer

### validate_full_name(name)
**Purpose**: Validate full name field with security checks.

**Returns**: Tuple of (valid, message, details)

**Validation Rules**:
- Required field (min 1 character after strip)
- Minimum 2 characters
- No digits allowed
- Only letters, spaces, apostrophes, hyphens
- Maximum 2 consecutive spaces

---

### validate_email(email)
**Purpose**: Validate email address with RFC 5321 compliance and security checks.

**Returns**: Tuple of (valid, message, details)

**Validation Rules**:
- Required field
- Length: 6-320 characters
- No spaces allowed
- Must contain exactly one '@' symbol
- Local part (before @): max 64 chars, alphanumeric start/end, allows ._+-
- Domain part (after @): must have dot, valid TLD (2-63 chars, letters only)
- Blocks disposable email domains
- No consecutive dots in local or domain parts

**Reference**: https://whoapi.com/blog/understanding-valid-email-address-formats-a-short-guide/

---

### validate_username(username)
**Purpose**: Validate username with security and format checks.

**Returns**: Tuple of (valid, message, details)

**Validation Rules**:
- Required field
- Length: 4-16 characters
- Must start with letter (not number)
- No spaces allowed
- Only letters, numbers, underscores
- No consecutive underscores

---

### validate_message(message)
**Purpose**: Validate message with XSS and SQL injection detection.

**Returns**: Tuple of (valid, message, details, threats)

**Validation Rules**:
- Required field
- Maximum 250 characters
- Blocks SQL keywords: SELECT, DROP, INSERT, DELETE, UPDATE, UNION, etc.
- Blocks XSS patterns: `<script>`, `<iframe>`, `javascript:`, event handlers
- Blocks admin panel references: admin, login, wp-admin, phpmyadmin

---

### sanitize_* functions
**Purpose**: Clean and normalize input for safe database storage.

**Functions**:
- `sanitize_full_name(name)`: Removes digits and invalid chars, formats to Title Case
- `sanitize_email(email)`: Removes spaces, normalizes to lowercase
- `sanitize_username(username)`: Removes invalid chars, normalizes to lowercase
- `sanitize_message(message)`: 9-layer sanitization (removes scripts, HTML entities, SQL keywords)

**Returns**: Tuple of (sanitized_value, was_sanitized)

---

### validate_and_sanitize_form(form_data)
**Purpose**: Main validation function for all form fields.

**Parameters**:
- `form_data` (dict): Dictionary with keys: full_name, email, username, message

**Returns**: Dictionary containing:
- `validation`: Per-field validation results
- `sanitized`: Sanitized values for each field
- `errors`: List of error messages
- `summary`: List of sanitization actions
- `all_valid`: Boolean overall validity
- `has_empty_fields`: Boolean if required fields missing

---

## Global Variables

### DICTIONARY_WORDS
Combined list from `load_dictionary()` + `load_nltk_words()`, deduplicated and sorted.

**Usage**: Used to find dictionary words inside passwords

**Performance Note**: Large NLTK corpus may slow down password checking due to substring matching loop

---

### COMMON_PASSWORDS
Short hardcoded list of very common passwords that immediately mark a password as weak.

**Examples**: "password", "123456", "qwerty", "admin", "letmein"

---

### Color Constants
Used to color-code verdicts in the GUI:
- `COLOR_WEAK = "#ef4444"` (red)
- `COLOR_MOD = "#f59e0b"` (orange)
- `COLOR_STRONG = "#22c55e"` (green)

---

### SQL_KEYWORDS
List of SQL keywords to detect injection attempts in messages.

---

### DANGEROUS_PATTERNS
Regex patterns to detect XSS and malicious code in messages.

---

### DISPOSABLE_DOMAINS
List of temporary/disposable email service domains to block.

---

## GUI Features

### Enter Key Binding
`root.bind_all("<Return>", ...)` allows users to press Enter to trigger password analysis without clicking the button.

---

### Conditional Scrollbars
Scrollbars appear only when content exceeds the visible area:
- Message input field (web validator)
- Password generator results
- Password strength details
- Form validation results

---

### Inline Validation Feedback
Web form validator shows:
- ✓ Valid (green) - Field passes all checks
- ⚠ Sanitized (orange) - Field was cleaned
- ✗ Error (red) - Lists ALL violations separated by bullets (•)

---

## Version History

### Version 1.0
- Dark blue themed GUI (button-click to analyze)
- Veto logic for common passwords and dictionary words
- No NLTK integration
- Custom modal popup with white default theme
- 7-rule scoring system
- Debug printing of detected dictionary words

### Version 2.0 (Current)
**Added/Configured**:
- NLTK integration (optional corpus loader expands dictionary coverage)
- Custom modal popup with dark blue theme (matches main GUI)
- Password Generator & Hasher tab
- Web Form Validator & Sanitizer tab
- Text Encryptor/Decryptor tab
- Dictionary-based password checks (local + NLTK)
- Combined structural + veto checks for nuanced results
- Enter key binding for improved usability
- Conditional scrollbars across all tabs
- Inline validation showing ALL violations per field
- Green success indicators for valid fields
- Sanitization summaries with detailed notes
