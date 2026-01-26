import hashlib
import os
import random
import string

def generate_password(min_len=12, max_len=16):
    # Ensure password length at least min_len and contains at least one char from each class
    length = random.randint(min_len, max_len)
    classes = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice(string.punctuation),
    ]
    if length < len(classes):
        length = len(classes)
    remaining = random.choices(string.ascii_letters + string.digits + string.punctuation,
                               k=length - len(classes))
    pwd_list = classes + remaining
    random.shuffle(pwd_list)
    return ''.join(pwd_list)

def generate_and_hash_password(min_len=12, max_len=16):
    pwd = generate_password(min_len, max_len)
    salt = os.urandom(16)
    sha256_hash = hashlib.sha256(salt + pwd.encode('utf-8')).hexdigest()
    return pwd, sha256_hash, salt.hex()




