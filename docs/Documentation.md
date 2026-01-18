# Documentation

### load_dictionary()
Location: src/utils/dictionary.py

Purpose: Loads a local dictionary file (dictionary.txt) into a Python list used to detect words inside passwords.
 (reads a file in the same folder).
list of words (lowercase) keeps words with length >= 4
Reads a word list from disk so the app can check if a password contains common words like 'apple' or 'secret'
it prints debug messages and returns a small fallback list when dictionary.txt is missing

### load_nltk_words(min_len=4, max_len=None)
Location: src/utils/dictionary.py
 >>>>> adds more dictionary words from NLTK so the password checks are more thorough.

Purpose: Loads words from the NLTK corpus (if installed) and returns them filtered by length.
 min_len (default 4), max_len (none)
list of corpus words in lowercase meeting length rules
> NLTK import is now guarded with try/except block
> Returns [] if NLTK is not installed - NO CRASH
> Safe to use - app works fine without NLTK using local dictionary only

### generate_password(length)
Location: src/features/password_generator.py

Purpose: Generates random password with required character types.
Guarantees: 1 uppercase, 1 lowercase, 1 digit, 1 special char.
Then shuffles to prevent patterns.
Returns string password of specified length (8-16)

### hash_password(password)
Location: src/features/password_generator.py

Purpose: Creates SHA-256 hash with random salt.
Returns both the salt (as hex string) and the hash.
Salt is 16 bytes random, converted to hex for storage
Used for secure password verification later

### save_to_file(password, salt, hashed, timestamp)
Location: src/features/password_generator.py

Purpose: Saves password, salt, and hash to passwords.txt in required format.
Uses append mode to keep previous entries.
Salt is saved so passwords can be verified later.
Returns True if successful, False on error

### load_password_entries()
Location: src/features/password_generator.py

Purpose: Loads all password entries from the file.
Returns a list of dictionaries containing password data.
Each dict has: timestamp, password, salt, hash
Returns empty list if file doesn't exist or on error

### verify_password_hash(password, entries)
Location: src/features/password_generator.py

Purpose: Verifies entered password against saved hashes using salt.
Loops through entries, reconstructs hash with saved salt, compares.
Returns timestamp string if match found, None if no match

### evaluate_password_strength(password)
Location: src/features/password_strength.py
>>>>>  This is the main checker: it tests password, warns if it's a known/common password or contains real words, and shows Weak/Moderate/Strong plus tips for a better password.
main password assessor

Returns tuple: (rating, color, feedback_messages)
 - rating: "WEAK", "MODERATE", or "STRONG"
 - color: hex color code for display (#ef4444, #f59e0b, #22c55e)
 - feedback_messages: list of strings

Returns early with warning if input empty.

## Runs Structural checks (5) 
1. length >= 12
2. has uppercase
3. lowercase
4. digits
5. symbols

## and separately Veto checks (2) 
> common passwords and dictionary-word containment 
1. Checks exact common passwords list and
2. Check if any dictionary word appears inside the password

WHERE
"Structural checks" = tests of the password's shape (length, uppercase, lowercase, digits, symbols). measure how the password is built.
"Veto checks" = rules that immediately mark the password WEAK regardless of score (common password or contains a real dictionary word). They "veto" a good score basically.
   
*Score totals up to 7; then chooses final verdict:*

1. Weak if common or contains dictionary word OR score <= 4
2. Moderate if score 5–6
3. Strong otherwise

> 5 structural checks + 2 hidden checks (not common + not dictionary) total max 7.
> 1. Strong requires no veto and effectively score == 7
> 2. moderate is score 5–6
> 3. weak is automatic if veto or score <= 4


**Shows details and colored verdict.**
Prints detected dictionary words to terminal (debug)
Where used: called by GUI check_password() method and Enter key binding.


## GUI Components

### MainMenu
Location: src/gui/main_menu.py

Purpose: Main menu window with navigation to password tools.
Shows two large buttons with hover effects:
 - "CHECK PASSWORD STRENGTH" - glows cyan (#38bdf8) on hover
 - "GENERATE RANDOM PASSWORD" - glows cyan (#38bdf8) on hover
Has quit button for clean exit
Hides itself when tool window opens, shows again on back button

### PasswordStrengthWindow
Location: src/gui/password_strength_tab.py

Purpose: Password strength analyzer window.
Features:
 - Single password input field
 - "ANALYZE PASSWORD STRENGTH" button
 - Enter key binding for quick analysis
 - Color-coded verdict display (WEAK/MODERATE/STRONG)
 - Detailed feedback with bullet points
 - "BACK TO MENU" button to return to main menu

### PasswordGeneratorWindow
Location: src/gui/password_generator_tab.py

Purpose: Password generator window with hashing and verification.
Features:
 - Length dropdown (8-16 characters)
 - "GENERATE PASSWORD" button
 - Display area showing password and hash
 - "CLEAR DISPLAY (SECURITY)" button
 - "VERIFY PASSWORD" button (opens verification modal)
 - "BACK TO MENU" button to return to main menu


## Other notes

#### the function does a case-insensitive check for COMMON_PASSWORDS (it compares pwd.lower()) and 
#### checks dictionary words against pwd.lower() too.

DICTIONARY_WORDS: combined list from load_dictionary() + load_nltk_words(), deduplicated and sorted. Used to find dictionary words inside a password.
NOTE: (on performance) if DICTIONARY_WORDS becomes large (NLTK), the loop that checks "if word in pwd.lower()" will be slower

COMMON_PASSWORDS: a short hardcoded list of very common passwords that immediately mark a password weak.
Color constants: used to color-code the verdict in the GUI.
Enter binding: Enter key support on all input fields to trigger analysis/generation easily!



### Version 1

1. Dark blue themed GUI (To start application function, must click button)
2. Veto logic in evaluate_password: if the password is in COMMON_PASSWORDS or contains a dictionary word, the password becomes WEAK immediately >> helps catch poor passwords that look complex but include real words.
3. No NLTK integration.
4. Custom modal popup; white default theme.
5. 7 rule scoring

6. Debug printing of detected dictionary words: helps trace why a password was flagged.
 only for debugging and not shown in the GUI.

### Version 2
ADDED / Configured

1. With NLTK integration --- Optional NLTK corpus loader (load_nltk_words): [ expands dictionary coverage when available ]
2. Custom modal popup; dark blue custom theme consistent with main GUI.
3. Dictionary-based checks 
Local dictionary loader (load_dictionary): lets the app detect real words inside passwords 
4. Combined structural checks + veto checks give a more nuanced result (Weak/Moderate/Strong).
#### Custom themed pop-up warning: consistent UI style and clearer user messaging.
#### Enter key binding: improves usability (press Enter to run analysis).

Previously: local file only, pop-up message GUI is white
Current: local file and NLTK, Pop-up message GUI now matches dark blue theme as main GUI

### Version 3 (Current - Unified Toolkit)
ADDED / Configured

1. Unified application with main menu - navigate between password strength and password generator tools
2. Cyan hover effects on both main menu buttons (#38bdf8)
3. Modular code structure - separated into src/gui/, src/features/, src/utils/
4. Back navigation - all tool windows have "BACK TO MENU" button
5. NLTK safety - guarded import prevents crashes if NLTK not installed
6. Password generator window - generate, hash, save, and verify passwords
7. Password verification feature - verify any previously generated password
8. Consistent dark blue theme across all windows and modals

File structure:
 - src/main.py (entry point)
 - src/gui/ (main_menu, password_strength_tab, password_generator_tab)
 - src/features/ (password_strength, password_generator)
 - src/utils/ (dictionary)

Previously: Single password strength analyzer tool only
Current: Unified toolkit with password strength analyzer AND password generator, menu-driven navigation between tools