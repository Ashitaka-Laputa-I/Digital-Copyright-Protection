import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from mutagen.mp3 import MP3
from mutagen.mp4 import MP4

# 解密音视频文件内容
def decrypt_audio_video_content(file_path, key):
    file_ext = os.path.splitext(file_path)[1].lower()

    if file_ext == '.mp3':
        # 解密MP3文件内容
        decrypt_mp3_content(file_path, key)
    elif file_ext == '.mp4':
        # 解密MP4文件内容
        decrypt_mp4_content(file_path, key)
    else:
        print(f"Unsupported file type: {file_ext}")


def decrypt_mp3_content(mp3_file, key):
    # 加载MP3文件
    audio = MP3(mp3_file)

    # 获取加密后的MP3文件数据
    with open(mp3_file, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    # 使用AES-256 CBC模式解密数据
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

    # 将解密后的数据写回MP3文件（这里假设直接覆盖原文件）
    with open(mp3_file, 'wb') as f:
        f.write(decrypted_data)


def decrypt_mp4_content(mp4_file, key):
    # 加载MP4文件
    video = MP4(mp4_file)

    # 获取加密后的MP4文件数据
    with open(mp4_file, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    # 使用AES-256 CBC模式解密数据
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

    # 将解密后的数据写回MP4文件（这里假设直接覆盖原文件）
    with open(mp4_file, 'wb') as f:
        f.write(decrypted_data)


# 嵌入序列号到音视频文件的元数据中
def embed_serial_number_to_audio_video(file_path, serial_number):
    file_ext = os.path.splitext(file_path)[1].lower()

    if file_ext == '.mp3':
        audio = MP3(file_path)
        audio['TXXX:SerialNumber'] = serial_number
        audio.save(f'protected_{os.path.basename(file_path)}')
    elif file_ext == '.mp4':
        video = MP4(file_path)
        video['©sn'] = serial_number
        video.save(f'protected_{os.path.basename(file_path)}')


# 加密音视频文件内容
def encrypt_audio_video_content(file_path, key):
    file_ext = os.path.splitext(file_path)[1].lower()

    if file_ext == '.mp3':
        # 加密MP3文件内容
        encrypt_mp3_content(file_path, key)
    elif file_ext == '.mp4':
        # 加密MP4文件内容
        encrypt_mp4_content(file_path, key)
    else:
        print(f"Unsupported file type: {file_ext}")


def encrypt_mp3_content(mp3_file, key):
    # 加载MP3文件
    audio = MP3(mp3_file)

    # 获取MP3文件的原始数据
    with open(mp3_file, 'rb') as f:
        audio_data = f.read()

    # 使用AES-256 CBC模式加密数据
    backend = default_backend()
    iv = os.urandom(16)  # 随机生成初始化向量
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(audio_data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # 将加密后的数据写回MP3文件（这里假设直接覆盖原文件）
    with open(mp3_file, 'wb') as f:
        f.write(iv + encrypted_data)


def encrypt_mp4_content(mp4_file, key):
    # 加载MP4文件
    video = MP4(mp4_file)

    # 获取MP4文件的原始数据
    with open(mp4_file, 'rb') as f:
        video_data = f.read()

    # 使用AES-256 CBC模式加密数据
    backend = default_backend()
    iv = os.urandom(16)  # 随机生成初始化向量
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(video_data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # 将加密后的数据写回MP4文件（这里假设直接覆盖原文件）
    with open(mp4_file, 'wb') as f:
        f.write(iv + encrypted_data)
