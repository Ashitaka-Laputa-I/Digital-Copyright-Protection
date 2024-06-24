import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from PIL import Image
import numpy as np


# 嵌入序列号到照片的元数据中
def embed_serial_number_to_photo(photo_path, serial_number):
    image = Image.open(photo_path)

    # 在图像描述中添加序列号信息
    image.info['serial_number'] = serial_number

    # 保存带有序列号的图像
    output_path = f'protected_{os.path.basename(photo_path)}'
    image.save(output_path)


# 加密照片内容
def encrypt_photo_content(photo_path, key):
    # 加载图片文件
    image = Image.open(photo_path)

    # 将图像转换为字节数据
    image_bytes = image.tobytes()

    # 使用AES-256 CBC模式加密图像数据
    backend = default_backend()
    iv = os.urandom(16)  # 随机生成初始化向量
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(image_bytes) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # 保存加密后的图像数据
    encrypted_image = Image.frombytes(image.mode, image.size, encrypted_data)
    output_path = f'encrypted_{os.path.basename(photo_path)}'
    encrypted_image.save(output_path)

    return output_path


# 解密照片内容
def decrypt_photo_content(photo_path, key):
    # 加载加密后的图片文件
    encrypted_image = Image.open(photo_path)

    # 将加密图像数据转换为字节数据
    encrypted_image_bytes = encrypted_image.tobytes()

    # 使用AES-256 CBC模式解密图像数据
    backend = default_backend()
    iv = encrypted_image_bytes[:16]  # 从图像数据中提取初始化向量
    encrypted_data = encrypted_image_bytes[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

    # 保存解密后的图像数据
    decrypted_image = Image.frombytes(encrypted_image.mode, encrypted_image.size, decrypted_data)
    output_path = f'decrypted_{os.path.basename(photo_path)}'
    decrypted_image.save(output_path)

    return output_path


def embed_watermark(image_path, serial_number):
    # 打开输入图像
    image = Image.open(image_path)
    image = image.convert('RGB')
    image_array = np.array(image)

    # 将水印文本转换为二进制
    watermark_bin = ''.join(format(ord(char), '08b') for char in serial_number)
    watermark_length = len(watermark_bin)

    # 嵌入水印
    rows, cols, _ = image_array.shape
    binary_index = 0
    for row in range(rows):
        for col in range(cols):
            for color in range(3):  # R, G, B 通道
                if binary_index < watermark_length:
                    # 修改低位比特为水印位
                    image_array[row, col, color] = (image_array[row, col, color] & 0xFE) | int(watermark_bin[binary_index])
                    binary_index += 1

    # 保存带水印的图像，覆盖原文件
    watermarked_image = Image.fromarray(image_array)
    watermarked_image.save(image_path)


def extract_watermark(image_path, watermark_length):
    # 打开图像
    image = Image.open(image_path)
    image = image.convert('RGB')
    image_array = np.array(image)

    # 提取水印
    rows, cols, _ = image_array.shape
    binary_index = 0
    watermark_bin = ''
    for row in range(rows):
        for col in range(cols):
            for color in range(3):  # R, G, B 通道
                if binary_index < watermark_length * 8:
                    watermark_bin += str(image_array[row, col, color] & 1)
                    binary_index += 1

    # 将二进制水印转换为文本
    watermark_text = ''
    for i in range(0, len(watermark_bin), 8):
        byte = watermark_bin[i:i+8]
        watermark_text += chr(int(byte, 2))

    return watermark_text