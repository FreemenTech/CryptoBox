🔐 CryptoBox

CryptoBox is a Python CLI tool designed to securely encrypt and decrypt files, with the user placed at the center of the security process.

The project relies exclusively on modern, industry-standard cryptographic primitives, with a clean architecture, strong error handling, and a simple but professional command-line interface.

✨ Features

🔒 Password-based file encryption

Secure key derivation using PBKDF2-HMAC-SHA256

Authenticated encryption with AES-256-GCM

🔑 AES file encryption with password-protected key

Random AES key generation

AES key encrypted using a password

🧾 Structured encrypted file format

Magic header to detect encryption mode

Embedded salt and nonce for safe decryption

🛡️ Integrity & authenticity

Automatic detection of wrong password or corrupted files

🚫 Safe failure

Clear, user-friendly error messages

No silent corruption or partial decryption

🧑‍💻 Beginner-friendly, professional-grade

Simple CLI for non-technical users

Clean internal design suitable for code review

🔐 Cryptography Overview

CryptoBox follows best practices used in real-world systems:

Component	Algorithm
Key derivation	PBKDF2-HMAC-SHA256 (300,000 iterations)
Symmetric encryption	AES-256-GCM
Randomness	OS-level secure RNG
Authentication	Built-in AEAD (GCM)

❗ No insecure algorithms, no custom crypto.

📂 Encryption Modes
1️⃣ Password-Based Encryption

A key is derived from the user’s password using PBKDF2

The file is encrypted with AES-256-GCM

Encrypted file contains:

MAGIC | SALT | NONCE | CIPHERTEXT


✔ Simple
✔ Portable
✔ Ideal for personal file protection

2️⃣ AES Encryption with Password-Protected Key

A random AES-256 key is generated

The file is encrypted using this AES key

The AES key itself is encrypted using a password

✔ Separation of data & key
✔ Better for larger workflows
✔ Suitable for reuse and automation

🖥️ Command Line Interface

CryptoBox provides an interactive CLI with:

Clear menus

Input validation

File existence checks

Safe overwrite prevention

Colored output using Rich

Example:

python main.py

⚠️ Error Handling

CryptoBox safely handles:

Wrong passwords

Corrupted or truncated files

Invalid encryption formats

Missing or inaccessible files

Permission issues

All cryptographic failures are detected and reported, never ignored.

📦 Dependencies

Python 3.9+

cryptography

rich

Install dependencies:

pip install cryptography rich

🎯 Project Scope & Level

This project is designed as:

✅ A solid end-of-beginner cryptography project

✅ A GitHub-ready portfolio tool

✅ A foundation for more advanced crypto systems

It intentionally avoids over-engineering while respecting professional security standards.

🚀 Possible Improvements

RSA-protected AES keys

Metadata signing

File streaming (large files)

Cross-platform packaging

Automated tests

🧠 Educational Value

CryptoBox demonstrates:

Proper password-based encryption

Safe key management principles

AEAD usage

Secure file format design

Professional error handling

📜 License

MIT License — free to use, modify, and distribute.