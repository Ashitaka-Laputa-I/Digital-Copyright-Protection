import os
from cryptography.hazmat.backends import default_backend
from PyPDF2 import PdfReader, PdfWriter
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


# 解密PDF文档内容
def decrypt_pdf_content(pdf_path, key):
    with open(pdf_path, 'rb') as f:
        reader = PdfReader(f)
        writer = PdfWriter()

        for page in range(len(reader.pages)):
            encrypted_data = reader.pages[page].extract_text()  # 提取加密内容，这里简化为提取文本

            # 使用AES-256 CBC模式解密文档内容
            backend = default_backend()
            iv = encrypted_data[:16]
            encrypted_data = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

            # 写入解密后的内容到新的PDF文件
            page = reader.pages[page]
            page.merge_page(reader.pages[page.page_number])
            writer.add_page(page)

        with open(f'decrypted_{os.path.basename(pdf_path)}', 'wb') as output_file:
            writer.write(output_file)


# 嵌入序列号到PDF文档的元数据中
def embed_serial_number_to_pdf(pdf_path, serial_number):
    with open(pdf_path, 'rb') as f:
        reader = PdfReader(f)
        writer = PdfWriter()

        # 将序列号嵌入到PDF元数据中
        metadata = reader.metadata
        metadata['/SerialNumber'] = serial_number

        for page in range(len(reader.pages)):
            writer.add_page(reader.pages[page])

        writer.add_metadata(metadata)

        # 写入带有序列号的PDF文件
        with open(f'protected_{os.path.basename(pdf_path)}', 'wb') as output_file:
            writer.write(output_file)


# 加密PDF文档内容
def encrypt_pdf_content(pdf_path, key):
    with open(pdf_path, 'rb') as f:
        reader = PdfReader(f)
        writer = PdfWriter()

        for page in range(len(reader.pages)):
            page_content = reader.pages[page].extract_text()  # 提取文档内容，这里简化为提取文本

            # 使用AES-256 CBC模式加密文档内容
            backend = default_backend()
            iv = os.urandom(16)  # 随机生成初始化向量
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(page_content.encode('utf-8')) + padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # 写入加密后的内容到新的PDF文件
            page = reader.pages[page]
            page.merge_page(reader.pages[page.page_number])
            writer.add_page(page)

        with open(f'encrypted_{os.path.basename(pdf_path)}', 'wb') as output_file:
            writer.write(output_file)