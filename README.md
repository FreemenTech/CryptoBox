# 🔐 CryptoBox v2.0

Secure file encryption CLI tool built with modern, audited cryptographic primitives.

CryptoBox gives you two ways to encrypt files — a password you remember, or a random AES key protected by a password — with zero compromise on security.

## Features

- **AES-256-GCM** authenticated encryption (AEAD)
- **PBKDF2-HMAC-SHA256** key derivation (600,000 iterations, OWASP 2023)
- **AAD-protected headers** — magic bytes, salt, and nonce are tamper-proof
- **Two interfaces** — interactive menu for humans, scriptable CLI for automation
- **Format detection** — wrong decryption mode is caught with a clear message
- **Safe failure** — partial outputs are cleaned up, no silent corruption

## Quick Start

```bash
pip install cryptography rich typer
```

### CLI Mode

```bash
# Encrypt with password
python main.py encrypt password secret.txt secret.enc

# Decrypt with password
python main.py decrypt password secret.enc secret.txt

# Encrypt with AES key (key protected by password)
python main.py encrypt aes secret.txt secret.enc --key-name mykey

# Decrypt with AES key
python main.py decrypt aes secret.enc secret.txt --key-name mykey

# Show help
python main.py --help
python main.py encrypt --help
```

### Interactive Menu

```bash
python main.py menu
```

## Encryption Modes

### 1 — Password-Based (CBX1)

A key is derived from your password. Simple, portable, ideal for personal file protection.

```
File format: [CBX1 (4B)] [SALT (16B)] [NONCE (12B)] [CIPHERTEXT + GCM TAG]
AAD scope:   CBX1 + SALT + NONCE (32 bytes)
```

### 2 — AES Key + Password (CBX2)

A random AES-256 key encrypts the file. The key itself is encrypted with your password and saved as a `.enc` file. Better for workflows where the same key encrypts multiple files.

```
File format: [CBX2 (4B)] [NONCE (12B)] [CIPHERTEXT + GCM TAG]
AAD scope:   CBX2 + NONCE (16 bytes)

Key file:    Uses CBX1 format (password-protected)
```

## Cryptography Overview

| Component          | Algorithm / Parameter          |
|--------------------|--------------------------------|
| Key derivation     | PBKDF2-HMAC-SHA256 (600,000 iterations) |
| Symmetric cipher   | AES-256-GCM                    |
| Authentication     | GCM built-in AEAD + AAD on headers |
| Randomness         | `os.urandom` (OS-level CSPRNG) |
| Nonce size         | 96 bits (GCM standard)         |
| Salt size          | 128 bits                       |

No insecure algorithms. No custom crypto.

## Security Properties

- **Keys never touch disk in plaintext** — AES keys are encrypted directly in memory before writing
- **Authenticated metadata** — AAD covers the full header, preventing silent tampering
- **Format-aware decryption** — using the wrong mode gives a clear error, not garbage output
- **Correct minimum size validation** — accounts for nonce + GCM tag, preventing crashes on truncated files
- **Password handling** — hidden input (getpass), confirmation on encrypt, minimum length enforced
- **Partial output cleanup** — failed operations remove incomplete files
- **Restrictive permissions** — key files get `chmod 600` on Unix systems
- **File size limit** — 2 GB cap prevents out-of-memory crashes

## Known Limitations

- **No streaming** — files are loaded entirely into memory (2 GB limit mitigates OOM)
- **No secure memory wiping** — Python's garbage collector may copy sensitive data; this is a language-level limitation
- **PBKDF2 vs Argon2** — Argon2id would be stronger against GPU attacks, but PBKDF2 at 600k iterations remains solid and avoids an extra dependency

## Project Structure

```
cryptobox/
├── main.py            Entry point
├── cli.py             Typer CLI (scriptable)
├── interactive.py     Menu-based interface
├── crypto_engine.py   All cryptographic operations
├── constants.py       Parameters and format specs
└── requirements.txt
```

## Dependencies

- Python 3.10+
- `cryptography` — audited crypto primitives
- `rich` — terminal formatting
- `typer` — CLI framework

## Possible Improvements

- Argon2id key derivation
- File streaming for large files
- RSA-protected AES keys
- Cross-platform packaging (PyPI)
- Automated test suite

## Author

**Freemen Houngbedji**
GitHub: [@FreemenTech](https://github.com/FreemenTech)

## License

MIT License — free to use, modify, and distribute.
