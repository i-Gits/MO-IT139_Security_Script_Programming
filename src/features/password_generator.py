# src/features/password_generator.py
import hashlib
import os
import random
import string

def generate_password(length=12):
    """Generate a strong password of specified length"""
    if length < 8:
        length = 8
    if length > 16:
        length = 16
    
    classes = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice(string.punctuation),
    ]
    
    if length < len(classes):
        length = len(classes)
    
    remaining = random.choices(
        string.ascii_letters + string.digits + string.punctuation,
        k=length - len(classes)
    )
    
    pwd_list = classes + remaining
    random.shuffle(pwd_list)
    return ''.join(pwd_list)

def hash_password(password):
    """Hash a password with salt, returns (salt_hex, hash_hex)"""
    salt = os.urandom(16)
    sha256_hash = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
    return salt.hex(), sha256_hash

def save_to_file(salt_hex, hash_hex, timestamp, password=None):
    """Save hash entry to file in format: [timestamp] | hash # salt (NO PASSWORD)"""
    try:
        os.makedirs('data', exist_ok=True)
        filepath = 'data/passwords.txt'
        
        # Format: [2026-01-26 22:15:19] | hash # salt
        # Password is NOT saved for security
        entry = f"[{timestamp}] | {hash_hex} # {salt_hex}\n"
        
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write(entry)
        
        return True
    except Exception as e:
        print(f"Error saving: {e}")
        return False