首先运行前请安装必要的库

```shell
tkinterdnd2~=0.3.0
cryptography~=42.0.8
PyPDF2~=3.0.1
mutagen~=1.47.0
Pillow~=10.3.0
numpy~=2.0.0
```

```shell
pip install -r requirements.txt
```

文件结构

```shell
digital_copyright_protection/
│
├── digital_copyright_protection.py # 主程序入口
├── device_info.py         # 获取授权机器硬件信息
├── hash_utils.py          # 生成和处理哈希值
├── aes_encryption.py      # AES 加密和解密功能
├── file_handlers/         # 各种文件类型处理
│   ├── txt_handler.py	   # 包含水印部分
│   ├── pdf_handler.py
│   ├── media_handler.py
│   ├── image_handler.py
│   ├── zip_handler.py
└── requirements.txt       # 项目依赖
├── test.txt			   # 测试文件
```

