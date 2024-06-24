import os
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


# 嵌入序列号到ZIP压缩包的文件名中
def embed_serial_number_to_zip(zip_file_path, serial_number):
    temp_dir = 'temp_extracted_files'
    os.makedirs(temp_dir, exist_ok=True)

    # 解压缩ZIP文件
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)

    # 修改文件名，在文件名中添加序列号信息
    for root, _, files in os.walk(temp_dir):
        for file in files:
            original_path = os.path.join(root, file)
            new_file_name = f"{os.path.splitext(file)[0]}_{serial_number}{os.path.splitext(file)[1]}"
            new_path = os.path.join(root, new_file_name)
            os.rename(original_path, new_path)

    # 重新压缩文件
    new_zip_path = f'protected_{os.path.basename(zip_file_path)}'
    with zipfile.ZipFile(new_zip_path, 'w') as zip_ref:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                zip_ref.write(file_path, os.path.relpath(file_path, temp_dir))

    # 清理临时目录
    os.rmdir(temp_dir)


def encrypt_file_content(file_path, key):
    # 读取文件内容
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # 生成随机的 IV
    iv = os.urandom(16)

    # 创建一个新的AES加密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 对文件内容进行填充
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # 加密文件内容
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # 将加密后的内容和初始向量写回文件
    with open(file_path, 'wb') as f:
        f.write(iv + ciphertext)


def encrypt_zip_content(zip_file_path, key):
    temp_dir = 'temp_extracted_files'
    os.makedirs(temp_dir, exist_ok=True)

    # 解压缩ZIP文件
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)

    # 加密解压后的文件内容
    for root, _, files in os.walk(temp_dir):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file_content(file_path, key)

    # 重新压缩文件
    new_zip_path = f'encrypted_{os.path.basename(zip_file_path)}'
    with zipfile.ZipFile(new_zip_path, 'w') as zip_ref:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                zip_ref.write(file_path, os.path.relpath(file_path, temp_dir))

    # 清理临时目录
    for root, _, files in os.walk(temp_dir):
        for file in files:
            os.remove(os.path.join(root, file))
    os.rmdir(temp_dir)

    print(f"Encrypted ZIP file created: {new_zip_path}")


def decrypt_file_content(file_path, key):
    # 读取文件内容
    with open(file_path, 'rb') as f:
        data = f.read()

    # 提取IV
    iv = data[:16]
    ciphertext = data[16:]

    # 创建一个新的AES解密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # 解密文件内容
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # 去除填充
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    # 将解密后的内容写回文件
    with open(file_path, 'wb') as f:
        f.write(plaintext)


def decrypt_zip_content(zip_file_path, key):
    temp_dir = 'temp_extracted_files'
    os.makedirs(temp_dir, exist_ok=True)

    # 解压缩ZIP文件
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)

    # 解密解压后的文件内容
    for root, _, files in os.walk(temp_dir):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt_file_content(file_path, key)

    # 重新压缩文件
    new_zip_path = f'decrypted_{os.path.basename(zip_file_path)}'
    with zipfile.ZipFile(new_zip_path, 'w') as zip_ref:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                zip_ref.write(file_path, os.path.relpath(file_path, temp_dir))

    # 清理临时目录
    for root, _, files in os.walk(temp_dir):
        for file in files:
            os.remove(os.path.join(root, file))
    os.rmdir(temp_dir)

    print(f"Decrypted ZIP file created: {new_zip_path}")