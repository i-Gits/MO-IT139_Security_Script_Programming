# Password generation with hashing and verification 

import hashlib
import os
import random
import string

OUTPUT_FILE = "passwords.txt"

def generate_password(length):
    """
    Generate random password with required character types.
    Guarantees: 1 uppercase, 1 lowercase, 1 digit, 1 special char.
    """
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special_chars = "!@#$%^&*()_-+={}[];:,.?"
    
    # Guarantee one of each required type
    password = [
        random.choice(uppercase),
        random.choice(lowercase),
        random.choice(digits),
        random.choice(special_chars)
    ]
    
    # Fill remaining length
    all_chars = uppercase + lowercase + digits + special_chars
    remaining_length = length - 4
    password.extend(random.choices(all_chars, k=remaining_length))
    
    # Shuffle to avoid predictable   patterns
    random.shuffle(password)
    
    return ''.join(password)

def hash_password(password):
    """
    Create SHA-256 hash with random salt.
    Returns: (salt_hex, hashed)
    """
    salt = os.urandom(16)
    hashed = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
    salt_hex = salt.hex()
    return salt_hex, hashed

def save_to_file(password, salt, hashed, timestamp):
    """Save password, salt, and hash to file"""
    try:
        entry = f"Timestamp: {timestamp}\n"
        entry += f"Password: {password}\n"
        entry += f"Salt: {salt}\n"
        entry += f"Hash: {hashed}\n"
        entry += "-" * 50 + "\n\n"
        
        with open(OUTPUT_FILE, 'a') as file:
            file.write(entry)
        
        return True
    except Exception as e:
        print(f"Error saving to file: {e}")
        return False

def load_password_entries():
    """Load all password entries from file"""
    entries = []
    
    try:
        if not os.path.exists(OUTPUT_FILE):
            return entries
            
        with open(OUTPUT_FILE, 'r') as file:
            content = file.read()
        
        blocks = content.split("-" * 50)
        
        for block in blocks:
            block = block.strip()
            if not block:
                continue
                
            lines = block.split('\n')
            entry = {}
            
            for line in lines:
                if line.startswith("Timestamp:"):
                    entry['timestamp'] = line.replace("Timestamp:", "").strip()
                elif line.startswith("Password:"):
                    entry['password'] = line.replace("Password:", "").strip()
                elif line.startswith("Salt:"):
                    entry['salt'] = line.replace("Salt:", "").strip()
                elif line.startswith("Hash:"):
                    entry['hash'] = line.replace("Hash:", "").strip()
            
            if 'password' in entry and 'salt' in entry and 'hash' in entry:
                entries.append(entry)
        
        return entries
        
    except Exception as e:
        print(f"Error loading password entries: {e}")
        return []

def verify_password_hash(password, entries):
    """
    Verify password against saved hashes.
    Returns: timestamp if match found, None otherwise
    """
    for entry in entries:
        try:
            # Convert hex salt back to bytes
            salt_bytes = bytes.fromhex(entry['salt'])
            
            # Hash the entered password with this salt
            entered_hash = hashlib.sha256(salt_bytes + password.encode('utf-8')).hexdigest()
            
            # Compare hashes
            if entered_hash == entry['hash']:
                return entry.get('timestamp', 'Unknown')
        except Exception:
            continue
    
    return None