# src/utils/dictionary.py
import os
import nltk
from nltk.corpus import words as nltk_words

HAS_NLTK = True

def load_dictionary() -> list[str]:
    """Load words from local dictionary.txt or fallback to defaults"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(script_dir, "..", "..", "data", "dictionary.txt")

    words = []

    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                words = [line.strip().lower() for line in f if len(line.strip()) > 3]
        except Exception as e:
            print(f"Error reading dictionary: {e}")
    else:
        print(f"Dictionary not found at {path} — using fallback")
        words = ["apple", "computer", "dragon", "monkey", "secret"]

    return words


def load_nltk_words(min_len: int = 4, max_len: int | None = None) -> list[str]:
    """Load filtered words from NLTK 'words' corpus"""
    if not HAS_NLTK:
        return []

    try:
        nltk.data.find('corpora/words')
    except LookupError:
        return []

    all_words = [w.lower() for w in nltk_words.words()]

    if max_len is None:
        return [w for w in all_words if len(w) >= min_len]
    return [w for w in all_words if min_len <= len(w) <= max_len]


# Global cached dictionary (loaded once)
DICTIONARY_WORDS = sorted(set(load_dictionary() + load_nltk_words()))