import hashlib


def generate_aes_key(password):
    return hashlib.sha256(password.encode('utf-8')).digest()