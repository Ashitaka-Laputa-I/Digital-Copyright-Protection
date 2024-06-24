from codes.file_handlers.txt_handler import *
from codes.file_handlers.image_handler import *
from codes.file_handlers.pdf_handler import *
from codes.file_handlers.zip_handler import *
from codes.file_handlers.media_handler import *
from codes.aes_encryption import generate_aes_key
from codes.device_info import generate_serial_number

import os
import re

import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinterdnd2 import TkinterDnD, DND_FILES


def embed_serial_number(file_path, serial_number):
    file_ext = os.path.splitext(file_path)[1].lower()

    if file_ext == '.pdf':
        embed_serial_number_to_pdf(file_path, serial_number)
    elif file_ext in ['.mp3', '.mp4']:
        embed_serial_number_to_audio_video(file_path, serial_number)
    elif file_ext in ['.jpg', '.jpeg', '.png']:
        embed_serial_number_to_photo(file_path, serial_number)
    elif file_ext == '.zip':
        embed_serial_number_to_zip(file_path, serial_number)
    elif file_ext == '.txt':
        embed_serial_number_to_txt(file_path, serial_number)
    else:
        print(f"Unsupported file type: {file_ext}")


def encrypt_file_content(file_path, key):
    file_ext = os.path.splitext(file_path)[1].lower()

    if file_ext == '.pdf':
        encrypt_pdf_content(file_path, key)
    elif file_ext in ['.mp3', '.mp4']:
        encrypt_audio_video_content(file_path, key)
    elif file_ext in ['.jpg', '.jpeg', '.png']:
        encrypt_photo_content(file_path, key)
    elif file_ext == '.zip':
        encrypt_zip_content(file_path, key)
    elif file_ext == '.txt':
        encrypt_txt_content(file_path, key)
    else:
        print(f"Unsupported file type: {file_ext}")


def authenticate_and_decrypt(file_path, password):
    key = generate_aes_key(password)
    decrypted_content = decrypt_file_content(file_path, key)
    if decrypted_content is None:
        print("Decryption failed. Unable to authenticate.")
        return

    file_ext = os.path.splitext(file_path)[1].lower()
    serial_number = None
    pattern = r'SerialNumber: ([0-9a-fA-F]+)'

    if file_ext == '.pdf':
        reader = PdfReader(decrypted_content)
        metadata = reader.getDocumentInfo()
        if '/SerialNumber' in metadata:
            serial_number = metadata['/SerialNumber']
    elif file_ext in ['.mp3', '.mp4']:
        if file_ext == '.mp3':
            audio = MP3(file_obj=decrypted_content)
            if 'TXXX:SerialNumber' in audio:
                serial_number = audio['TXXX:SerialNumber'].text[0]
        elif file_ext == '.mp4':
            video = MP4(file_obj=decrypted_content)
            if '©sn' in video:
                serial_number = video['©sn'][0]
    elif file_ext in ['.jpg', '.jpeg', '.png']:
        img = Image.open(decrypted_content)
        if 'serial_number' in img.info:
            serial_number = img.info['serial_number']
    elif file_ext == '.zip':
        with zipfile.ZipFile(decrypted_content, 'r') as zip_ref:
            for file in zip_ref.namelist():
                if file.startswith('SerialNumber'):
                    match = re.search(pattern, file)
                    if match:
                        serial_number = match.group(1)
                        break
    elif file_ext == '.txt':
        match = re.search(pattern, decrypted_content)
        if match:
            serial_number = match.group(1)

    if serial_number is not None and generate_serial_number() == serial_number:
        print("Authentication successful.")
        decrypted_content = re.sub(pattern, '', decrypted_content).strip()
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(decrypted_content)
    else:
        print("Authentication failed. Unauthorized access.")


def decrypt_file_content(file_path, key):
    file_ext = os.path.splitext(file_path)[1].lower()

    if file_ext == '.pdf':
        return decrypt_pdf_content(file_path, key)
    elif file_ext in ['.mp3', '.mp4']:
        return decrypt_audio_video_content(file_path, key)
    elif file_ext in ['.jpg', '.jpeg', '.png']:
        return decrypt_photo_content(file_path, key)
    elif file_ext == '.zip':
        return decrypt_zip_content(file_path, key)
    elif file_ext == '.txt':
        return decrypt_txt_content(file_path, key)
    else:
        print(f"Unsupported file type: {file_ext}")
        return None


def authenticate_and_decrypt(file_path, password):
    key = generate_aes_key(password)
    decrypted_content = decrypt_file_content(file_path, key)
    if decrypted_content is None:
        print("Decryption failed. Unable to authenticate.")
        return

    file_ext = os.path.splitext(file_path)[1].lower()
    serial_number = None
    pattern = r'SerialNumber: ([0-9a-fA-F]+)'

    if file_ext == '.pdf':
        reader = PdfReader(decrypted_content)
        metadata = reader.getDocumentInfo()
        if '/SerialNumber' in metadata:
            serial_number = metadata['/SerialNumber']
    elif file_ext in ['.mp3', '.mp4']:
        if file_ext == '.mp3':
            audio = MP3(file_obj=decrypted_content)
            if 'TXXX:SerialNumber' in audio:
                serial_number = audio['TXXX:SerialNumber'].text[0]
        elif file_ext == '.mp4':
            video = MP4(file_obj=decrypted_content)
            if '©sn' in video:
                serial_number = video['©sn'][0]
    elif file_ext in ['.jpg', '.jpeg', '.png']:
        img = Image.open(decrypted_content)
        if 'serial_number' in img.info:
            serial_number = img.info['serial_number']
    elif file_ext == '.zip':
        with zipfile.ZipFile(decrypted_content, 'r') as zip_ref:
            for file in zip_ref.namelist():
                if file.startswith('SerialNumber'):
                    match = re.search(pattern, file)
                    if match:
                        serial_number = match.group(1)
                        break
    elif file_ext == '.txt':
        match = re.search(pattern, decrypted_content)
        if match:
            serial_number = match.group(1)

    if serial_number is not None and generate_serial_number() == serial_number:
        print("Authentication successful.")
        decrypted_content = re.sub(pattern, '', decrypted_content).strip()
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(decrypted_content)
    else:
        print("Authentication failed. Unauthorized access.")


class App(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()

        self.title("File Protector")
        self.geometry("500x400")

        self.label = tk.Label(self, text="Drag and drop a file here", width=50, height=10)
        self.label.pack(pady=20)

        self.encrypt_button = tk.Button(self, text="Sign and Encrypt", command=self.sign_and_encrypt)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(self, text="Authenticate and Decrypt", command=self.authenticate_and_decrypt)
        self.decrypt_button.pack(pady=10)

        self.drop_target_register(DND_FILES)
        self.dnd_bind('<<Drop>>', self.drop)

        self.file_path = None

    def drop(self, event):
        self.file_path = event.data.strip('{}')
        self.label.config(text=f"File: {self.file_path}")

    def sign_and_encrypt(self):
        if not self.file_path:
            messagebox.showwarning("Warning", "Please drop a file first.")
            return

        password = simpledialog.askstring("Password", "Enter a password:", show='*')
        if not password:
            messagebox.showwarning("Warning", "Password cannot be empty.")
            return

        serial_number = generate_serial_number()
        embed_serial_number(self.file_path, serial_number)
        key = generate_aes_key(password)
        encrypt_file_content(self.file_path, key)

        messagebox.showinfo("Info", "File has been signed and encrypted.")

    def authenticate_and_decrypt(self):
        if not self.file_path:
            messagebox.showwarning("Warning", "Please drop a file first.")
            return

        password = simpledialog.askstring("Password", "Enter a password:", show='*')
        if not password:
            messagebox.showwarning("Warning", "Password cannot be empty.")
            return

        authenticate_and_decrypt(self.file_path, password)


if __name__ == "__main__":
    app = App()
    app.mainloop()
