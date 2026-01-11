# Documentation

### load_dictionary()

Purpose: Loads a local dictionary file (dictionary.txt) into a Python list used to detect words inside passwords.
 (reads a file in the same folder).
list of words (lowercase) keeps words with length >= 4
Reads a word list from disk so the app can check if a password contains common words like ‘apple’ or ‘secret’
it prints debug messages and returns a small fallback list when dictionary.txt is missing

### load_nltk_words(min_len=4, max_len=None)
 >>>>> adds more dictionary words from NLTK so the password checks are more thorough.

Purpose: Loads words from the NLTK corpus (if installed) and returns them filtered by length.
 min_len (default 4), max_len (none)
list of corpus words in lowercase meeting length rules
> If nltk is not installed the script will/might crash 
or it should return [] if the corpus isn't installed? idea is the code checks for the corpus word db without downloading it.
 [TO DO: CHECK]

with the current file, we import nltk unguarded at top 
> 1. if nltk is not installed the script will crash before load_nltk_words runs
  > a. either guard the import or
  > b. just state retain and ADD warning "current code will crash if nltk is not installed." 
Will have to "guard" the import in the future for imrpovment


### show_custom_warning(title, message)

>>>>> A custom popup that matches the app style and tells the user something is wrong.

Purpose: Show a small themed modal warning window  
 title (string), message (string).
 (displays popup) 
> So it opens a blocking popup that uses the app’s dark theme
> Called when the user submits empty input (evaluate_password)

### evaluate_password()
>>>>>  This is the main checker: it tests password, warns if it’s a known/common password or contains real words, and shows Weak/Moderate/Strong plus tips for a better password.
main password assessor

updates GUI widgets label_rating and label_details with a verdict and feedback.
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
2. Ceheck if any dictionary word appears inside the password

WHERE
"Structural checks" = tests of the password's shape (length, uppercase, lowercase, digits, symbols). measure how the password is built.
"Veto checks" = rules that immediately mark the password WEAK regardless of score (common password or contains a real dictionary word). They “veto” a good score basically.
   
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
Where used: button command and Enter binding.


## Other notes

#### the function does a case-insensitive check for COMMON_PASSWORDS (it compares pwd.lower()) and 
#### checks dictionary words against pwd.lower() too.

DICTIONARY_WORDS: combined list from load_dictionary() + load_nltk_words(), deduplicated and sorted. Used to find dictionary words inside a password.
NOTEE: (on performance) if DICTIONARY_WORDS becomes large (NLTK), the loop that checks "if word in pwd.lower()" will be slower

COMMON_PASSWORDS: a short hardcoded list of very common passwords that immediately mark a password weak.
Color constants: used to color-code the verdict in the GUI.
Enter binding: root.bind_all("<Return>", ...) *"invokes"* the Analyze button so users can press Enter to run the check easily!



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
Current: local file and NTLTK, Pop-up message GUI now matches dark blue theme as main GUI
