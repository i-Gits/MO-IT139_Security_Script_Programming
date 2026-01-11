# MO-IT139_Security_Script_Programming
Security Script Programming 2026


# PASSECURIST

What this app does:
- Lets a user type a password and analyzes strength.
- Checks structure (length, uppercase, lowercase, numbers, symbols).
- Flags immediately if password is a common password or contains dictionary words.
- Uses a local dictionary file and optionally NLTK words to detect your password strength

How to run:
1. (Optional) Install NLTK and download words corpus if you want larger dictionary checks:
   - python -m pip install nltk
   - python -m nltk.downloader words
2. Run app:
   - python "MO-IT139 Homework Password Strength Assessor....py"
3. Type a password and press Analyze or Enter.

Key files:
- dictionary.txt
    > optional local word list used by load_dictionary()
- main script
   > contains load_dictionary(), load_nltk_words(), evaluate_password(), show_custom_warning()
