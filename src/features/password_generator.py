import hashlib
import os
import random
import string

def generate_password():
    length = random.randint(8, 16)
    random_password = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation, k=length))
    return random_password

def generate_hashing(random_password):
    salt = os.urandom(16)
    sha256_hash = hashlib.sha256(salt + random_password.encode()).hexdigest()
    return sha256_hash

def generate_and_hash_password():
    random_password = generate_password()
    sha256_hash = generate_hashing(random_password)
    salt_hex = os.urandom(16).hex()
    return random_password, sha256_hash, salt_hex




