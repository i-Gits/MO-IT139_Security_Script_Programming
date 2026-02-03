# src/utils/genPassStorage.py
import os
from datetime import datetime

DATA_DIR = os.path.join(os.getcwd(), "data")
PASSWORD_FILE = os.path.join(DATA_DIR, "passwords.txt")


def ensure_data_dir():
    """Create data directory if it doesn't exist"""
    os.makedirs(DATA_DIR, exist_ok=True)

def save_password(sha256_hash: str, note: str = "") -> bool:
    """
    Append password to file with timestamp
    Returns True if saved successfully
    """
    try:
        ensure_data_dir()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] |  {sha256_hash}"
        if note:
            line += f"  # {note}"
        line += "\n"
        
        with open(PASSWORD_FILE, "a", encoding="utf-8") as f:
            f.write(line)
            
        return True
    except Exception as e:
        print(f"Error saving password: {e}")
        return False