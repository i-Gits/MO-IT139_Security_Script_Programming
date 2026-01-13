import tkinter as tk
from tkinter import messagebox
import re
import os 

import nltk
from nltk.corpus import words as nltk_words
HAS_NLTK = True
#NLTK import, when nltk is already downloaded


# --- function to load dictionary from txt file ---
def load_dictionary():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    full_path = os.path.join(script_dir, "dictionary.txt")
    
    print(f"debug: looking for dictionary at: {full_path}")
    
    words = []
    
    if os.path.exists(full_path):
        try:
            with open(full_path, "r") as file:
                for line in file:
                    cleaned_word = line.strip().lower()
            
                    # only add the word if it is longer than 3 letters
                
                    if len(cleaned_word) > 3:
                        words.append(cleaned_word)
                        
            print(f"success: loaded {len(words)} words (filtered > 3 letters).")
        except Exception as e:
            print(f"error reading file: {e}")
    else:
        print(f"warning: file not found at {full_path}")
        words = ["apple", "computer", "dragon", "monkey", "secret"]
        
    return words

# --- configuration ---
# [NOTE] Quick run on changes made: 
# > append NLTK words
# > remove duplicates
# > then return an alphabetically sorted list
# 
# MUST DO: (Run in powershell)
#NLTK
# python -m pip install --user nltk
#CORPUS 
# python -m nltk.downloader words 
"""
1. Install NLTK into that venv: 
& 'C:/Users/arc/env/Scripts/python.exe' -m pip install nltk

2. Download the words corpus (run after install): 
& 'C:/Users/arc/env/Scripts/python.exe' -m nltk.downloader words"""

def load_nltk_words(min_len=4, max_len=None):
    """
    return a list of words from the NLTK 'words' corpus:
    - all words are returned in lowercase
    - words are filtered by length 
        (default: keep words length >= min_len | So we don't get super short words like 'a', 'I', 'an', etc w/c would cause many false positives or matches inside passwords)
    - if NLTK or the 'words' corpus is not available, returns an empty list
    """

    # if we didn't import NLTK earlier, there's nothing to load
    if not HAS_NLTK:
        return []

    # check the words corpus is installed locally
    # ff it's missing, don't try to download here (that can freeze the GUI)
    try:
        nltk.data.find('corpora/words')
    except LookupError:
        # to install the corpus, run this in a shell:
        # py -m nltk.downloader words
        return []

    # Create a generator that yields each corpus word in lowercase.
     # load all corpus words into a list and convert to lowercase
    all_words = [w.lower() for w in nltk_words.words()]

    # filter by length and return
    if max_len is None:
        return [w for w in all_words if len(w) >= min_len]
    return [w for w in all_words if min_len <= len(w) <= max_len]



# 1. load the dictionary
DICTIONARY_WORDS = load_dictionary()

# add all NLTK words to the end of local list we already have
if HAS_NLTK:
    DICTIONARY_WORDS.extend(load_nltk_words())
#removes duplicates (set) and then sorts everything alphabetically.
DICTIONARY_WORDS = sorted(set(DICTIONARY_WORDS)) #SET(...) removes duplicates (no order)
#SORTED(...) makes a new list in alphabetical order
#WHY: merged two sources (local file + NLTK) = many words will appear in both, duplicates waste memory and slow checks (the loop may test the same word twice)
# 2. common passwords 
COMMON_PASSWORDS = [
    "password", "123456", "qwerty", "admin", "letmein", 
    "welcome", "login", "12345", "iloveyou"
]

# --- super cool hackerist theeme ---
BG_COLOR = "#0f172a"      # slate-900 (dark blue)
CARD_COLOR = "#1e293b"    # slate-800
TEXT_MAIN = "#e2e8f0"     # light grey
ACCENT_COLOR = "#38bdf8"  # sky blue
BTN_HOVER = "#0ea5e9"     # darker sky blue

# status colors
COLOR_WEAK = "#ef4444"    # red
COLOR_MOD = "#f59e0b"     # amber/orange
COLOR_STRONG = "#22c55e"  # green


# Simple dark-themed modal warning that matches the app colors.
# Replaces the OS/native messagebox so the dialog uses the hackerman style theme
# BG_COLOR and CARD_COLOR. Blocks the main window until the user
# clicks OK (same behavior as messagebox.showwarning).
def show_custom_warning(title, message):
    win = tk.Toplevel(root)
    win.title(title)
    win.configure(bg=BG_COLOR)
    tk.Label(win, text=message, bg=CARD_COLOR, fg=TEXT_MAIN, padx=12, pady=10).pack()
    tk.Button(win, text="OK", command=win.destroy, bg=ACCENT_COLOR, fg=BG_COLOR).pack(pady=8)
    win.transient(root); win.grab_set(); root.wait_window(win)


def evaluate_password():
    """analyzes the password against 7 criteria and updates the gui."""
    pwd = entry_pass.get()
    
    # --- 0. empty input check ---
    if not pwd:
        show_custom_warning("Input Required", "Please enter a password before checking.")
        return

    # analysis variables
    score = 0
    feedback_notes = []
    
    # --- 1. structural checks (5 criteria) ---
    # use (condition, "message if missing")
    checks = [
        (len(pwd) >= 12, "Length < 12."),
        (re.search(r"[A-Z]", pwd), "No uppercase."),
        (re.search(r"[a-z]", pwd), "No lowercase."),
        (re.search(r"[0-9]", pwd), "No numbers."),
        (re.search(r"[!@#$%^&*()_+=\-{}\[\]:;\"'<>,.?/|\\]", pwd), "No symbols.")
    ]
    
    # run the 5 structural checks
    for passed, note in checks:
        if passed:
            score += 1
        else:
            feedback_notes.append(note)

    # --- 2. veto checks (the common pwds & dictionary) ---
    is_common = pwd.lower() in COMMON_PASSWORDS
    
    # check if any dictionary word is found inside the password
    # lofic loops through every word in the loaded list
    has_dict_word = False
    found_word = ""  #  var to save the word


    for word in DICTIONARY_WORDS:
        if word in pwd.lower():
            has_dict_word = True
            found_word = word

            print(f"Detected dictionary word: {word}") # prints to terminal for debugging becauee this caused me much pain
            break # stop checking once found
    
    if is_common:
        feedback_notes.insert(0, "⚠ Common password detected. Don't get lazy!")
    if has_dict_word:
        feedback_notes.insert(0, f"⚠ Contains dictionary word: '{found_word}'")

    # update score for the "hidden" criteria (not common + not dictionary)

    # if they are not common/dict, we add points to reach the total of 7 criteria.
    if not is_common: score += 1
    if not has_dict_word: score += 1
    
    # --- 3. determine thee rating ---
    # rule: automatic weak if common or dictionary word
    if is_common or has_dict_word:
        final_rating = "WEAK"
        final_color = COLOR_WEAK
    
    # rule: weak if fails 3+ criteria (score < 5 out of 7)
    elif score <= 4: 
        final_rating = "WEAK"
        final_color = COLOR_WEAK
        
    # rule: moderate (meets 4-5 criteria, missing 1-2 important ones)
    # since we already handled "weak" (score <= 4), moderate is usually score 5 or 6
    elif score <= 6:
        final_rating = "MODERATE"
        final_color = COLOR_MOD
        
    # rule: strong (meets 6 or 7 criteria + no vetoes)
    else:
        final_rating = "STRONG"
        final_color = COLOR_STRONG
        feedback_notes = ["Excellent password structure! Keep it up."]

    # --- 4. update gui ---
    label_rating.config(text=f"VERDICT: {final_rating}", fg=final_color)
    
    # join the feedback notes into a bulleted list to look clen
    details_text = "\n".join([f"• {note}" for note in feedback_notes])
    label_details.config(text=details_text)


# --- gui layout ---
root = tk.Tk()
root.title("Password Strength Assessor")
root.geometry("500x530")
root.configure(bg=BG_COLOR)

# header
frame_header = tk.Frame(root, bg=BG_COLOR, pady=20)
frame_header.pack()
tk.Label(frame_header, text="PASSECURIST", font=("Segoe UI", 18, "bold"), fg=ACCENT_COLOR, bg=BG_COLOR).pack()
tk.Label(frame_header, text="A Basic Password Strength Analyzer by St3althSt4ck3rs.", font=("Segoe UI", 10), fg=TEXT_MAIN, bg=BG_COLOR).pack()

# input section
frame_input = tk.Frame(root, bg=CARD_COLOR, padx=20, pady=20)
frame_input.pack(fill="x", padx=20)

tk.Label(frame_input, text="Enter Password:", font=("Segoe UI", 11), fg=TEXT_MAIN, bg=CARD_COLOR).pack(anchor="w")

entry_pass = tk.Entry(frame_input, font=("Consolas", 12), width=24, bg="#334155", fg="white", insertbackground="white", relief="flat")
entry_pass.pack(pady=10, ipady=4, fill="x")

btn_check = tk.Button(frame_input, text="ANALYZE PASSWORD STRENGTH", command=evaluate_password,
                      bg=ACCENT_COLOR, fg="#0f172a", font=("Segoe UI", 10, "bold"),
                      relief="flat", activebackground=BTN_HOVER, cursor="hand2")
btn_check.pack(fill="x", pady=5)


##################################TADA~ we can just click enter for it to run!
# Use bind_all so the Return key will "press" the button no matter which widget has focus.
# This avoids issues where the Entry may lose focus or another widget captures the key.
root.bind_all("<Return>", lambda e: btn_check.invoke())
root.bind_all("<KP_Enter>", lambda e: btn_check.invoke())  # optional: numpad Enter
# ensure entry gets focus after the window appears
root.after(100, entry_pass.focus_set)
##################################

# results section
frame_result = tk.Frame(root, bg=BG_COLOR, padx=20, pady=20)
frame_result.pack(fill="both", expand=True)

label_rating = tk.Label(frame_result, text="VERDICT: WAITING...", font=("Segoe UI", 14, "bold"), fg="#64748b", bg=BG_COLOR)
label_rating.pack(pady=(0, 10))

# a separator line
tk.Frame(frame_result, height=2, bg=CARD_COLOR).pack(fill="x", pady=5)

label_details = tk.Label(frame_result, text="Enter a password to view security gaps and recommendations.", 
                         font=("Segoe UI", 10), fg="#94a3b8", bg=BG_COLOR, justify="left")
label_details.pack(anchor="w", pady=10)







root.mainloop()