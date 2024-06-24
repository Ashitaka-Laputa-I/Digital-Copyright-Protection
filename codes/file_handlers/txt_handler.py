import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def embed_serial_number_to_txt(txt_path, serial_number):
    with open(txt_path, 'r', encoding='utf-8') as file:
        content = file.read()

    with open(txt_path, 'w', encoding='utf-8') as file:
        file.write(f"SerialNumber: {serial_number}\n{content}")


def encrypt_txt_content(txt_path, key):
    with open(txt_path, 'r', encoding='utf-8') as file:
        content = file.read()

    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(content.encode('utf-8')) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(txt_path, 'wb') as file:
        file.write(iv + encrypted_data)


def decrypt_txt_content(txt_path, key):
    with open(txt_path, 'rb') as file:
        iv = file.read(16)
        encrypted_data = file.read()

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
    return decrypted_data.decode('utf-8')

