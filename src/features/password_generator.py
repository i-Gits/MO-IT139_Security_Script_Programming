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
    md5_hash = hashlib.md5(salt + random_password.encode()).hexdigest()
    return sha256_hash, md5_hash







print("Generating a random password...")

password = generate_password()
print("Generated Password:", password)

sha256_hash, md5_hash = generate_hashing(password)
print("SHA256 Hash:", sha256_hash)
print("MD5 Hash:", md5_hash)