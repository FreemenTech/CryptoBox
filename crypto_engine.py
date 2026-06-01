"""
CryptoBox v2.0 — Cryptographic engine.

All encryption, decryption, and key management logic.
No UI concerns — this module is used by both interactive and CLI modes.

Security properties:
    - AES-256-GCM with AAD on all headers
    - PBKDF2-HMAC-SHA256 at 600,000 iterations
    - Keys NEVER touch disk in plaintext
    - Format-aware decryption (detects wrong mode)
    - Validated minimum file sizes (nonce + tag accounted for)
"""

import os
import stat
import platform
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from constants import (
    MAGIC_PASSWORD,
    MAGIC_AES_KEY,
    PBKDF2_ITERATIONS,
    AES_KEY_SIZE,
    SALT_SIZE,
    NONCE_SIZE,
    MAX_FILE_SIZE,
    MIN_PASSWORD_FILE,
    MIN_AES_FILE,
    MIN_KEY_FILE,
)


# ══════════════════════════════════════════════════════════════
#                       INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive AES-256 key from password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _validate_input_file(path: str) -> None:
    """Validate that a file exists, is readable, and within size limits."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")

    size = os.path.getsize(path)
    if size == 0:
        raise ValueError("File is empty")
    if size > MAX_FILE_SIZE:
        raise ValueError(
            f"File too large ({size:,} bytes). "
            f"Maximum supported: {MAX_FILE_SIZE:,} bytes"
        )


def _validate_output_path(path: str) -> None:
    """Validate that the output path is writable and won't overwrite."""
    if os.path.exists(path):
        raise FileExistsError(f"Output file already exists: {path}")

    parent = os.path.dirname(path) or "."
    if not os.access(parent, os.W_OK):
        raise PermissionError(f"Cannot write to directory: {parent}")


def _set_restrictive_permissions(path: str) -> None:
    """Set file permissions to owner-only (600) on Unix systems."""
    if platform.system() != "Windows":
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass  # best effort — don't fail the operation


def _detect_format(raw: bytes, min_size: int) -> tuple[bytes, bytes]:
    """Read magic header and validate minimum size.

    Returns (magic, raw) or raises with a helpful message
    if the file was encrypted with the other mode.
    """
    if len(raw) < 4:
        raise ValueError("File too small — not a CryptoBox file")

    magic = raw[:4]
    if len(raw) < min_size:
        raise ValueError("File too small — corrupted or truncated")

    return magic, raw


# ══════════════════════════════════════════════════════════════
#                  PASSWORD-BASED ENCRYPTION
# ══════════════════════════════════════════════════════════════

def encrypt_file_password(input_file: str, output_file: str, password: str) -> None:
    """Encrypt a file with a password.

    Format: MAGIC_PASSWORD | SALT | NONCE | CIPHERTEXT+TAG
    AAD: MAGIC_PASSWORD + SALT + NONCE (32 bytes)
    """
    _validate_input_file(input_file)
    _validate_output_path(output_file)

    try:
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        key = _derive_key(password, salt)

        with open(input_file, "rb") as f:
            data = f.read()

        header = MAGIC_PASSWORD + salt + nonce
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, header)

        with open(output_file, "wb") as f:
            f.write(header + ciphertext)

    except (InvalidTag, ValueError) as e:
        # Clean up partial output on failure
        if os.path.exists(output_file):
            os.remove(output_file)
        raise ValueError(f"Encryption failed: {e}")

    except (PermissionError, OSError) as e:
        if os.path.exists(output_file):
            os.remove(output_file)
        raise IOError(f"File system error: {e}")


def decrypt_file_password(input_file: str, output_file: str, password: str) -> None:
    """Decrypt a password-encrypted file."""
    _validate_input_file(input_file)
    _validate_output_path(output_file)

    try:
        with open(input_file, "rb") as f:
            raw = f.read()

        magic, raw = _detect_format(raw, MIN_PASSWORD_FILE)

        if magic == MAGIC_AES_KEY:
            raise ValueError(
                "This file uses AES key mode (CBX2). "
                "Use AES key decryption instead."
            )
        if magic != MAGIC_PASSWORD:
            raise ValueError("Not a CryptoBox file — unrecognized format")

        salt = raw[4:4 + SALT_SIZE]
        nonce = raw[4 + SALT_SIZE:4 + SALT_SIZE + NONCE_SIZE]
        ciphertext = raw[4 + SALT_SIZE + NONCE_SIZE:]
        header = raw[:4 + SALT_SIZE + NONCE_SIZE]

        key = _derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, header)

        with open(output_file, "wb") as f:
            f.write(plaintext)

    except InvalidTag:
        if os.path.exists(output_file):
            os.remove(output_file)
        raise ValueError("Wrong password or corrupted file")

    except (FileNotFoundError, PermissionError, OSError) as e:
        if os.path.exists(output_file):
            os.remove(output_file)
        raise IOError(f"File system error: {e}")


# ══════════════════════════════════════════════════════════════
#                  AES KEY-BASED ENCRYPTION
# ══════════════════════════════════════════════════════════════

def encrypt_file_aes(input_file: str, output_file: str, aes_key: bytes) -> None:
    """Encrypt a file with an AES-256 key.

    Format: MAGIC_AES_KEY | NONCE | CIPHERTEXT+TAG
    AAD: MAGIC_AES_KEY + NONCE (16 bytes)
    """
    _validate_input_file(input_file)
    _validate_output_path(output_file)

    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError(
            f"Invalid AES key size: expected {AES_KEY_SIZE} bytes, "
            f"got {len(aes_key)}"
        )

    try:
        nonce = os.urandom(NONCE_SIZE)
        header = MAGIC_AES_KEY + nonce

        with open(input_file, "rb") as f:
            data = f.read()

        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, data, header)

        with open(output_file, "wb") as f:
            f.write(header + ciphertext)

    except (InvalidTag, ValueError) as e:
        if os.path.exists(output_file):
            os.remove(output_file)
        raise ValueError(f"Encryption failed: {e}")

    except (PermissionError, OSError) as e:
        if os.path.exists(output_file):
            os.remove(output_file)
        raise IOError(f"File system error: {e}")


def decrypt_file_aes(input_file: str, output_file: str, aes_key: bytes) -> None:
    """Decrypt an AES key-encrypted file."""
    _validate_input_file(input_file)
    _validate_output_path(output_file)

    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError(
            f"Invalid AES key size: expected {AES_KEY_SIZE} bytes, "
            f"got {len(aes_key)}"
        )

    try:
        with open(input_file, "rb") as f:
            raw = f.read()

        magic, raw = _detect_format(raw, MIN_AES_FILE)

        if magic == MAGIC_PASSWORD:
            raise ValueError(
                "This file uses password mode (CBX1). "
                "Use password decryption instead."
            )
        if magic != MAGIC_AES_KEY:
            raise ValueError("Not a CryptoBox file — unrecognized format")

        nonce = raw[4:4 + NONCE_SIZE]
        ciphertext = raw[4 + NONCE_SIZE:]
        header = raw[:4 + NONCE_SIZE]

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, header)

        with open(output_file, "wb") as f:
            f.write(plaintext)

    except InvalidTag:
        if os.path.exists(output_file):
            os.remove(output_file)
        raise ValueError("Wrong key or corrupted file")

    except (FileNotFoundError, PermissionError, OSError) as e:
        if os.path.exists(output_file):
            os.remove(output_file)
        raise IOError(f"File system error: {e}")


# ══════════════════════════════════════════════════════════════
#                      KEY MANAGEMENT
# ══════════════════════════════════════════════════════════════

def generate_aes_key(key_name: str, password: str) -> bytes:
    """Generate a random AES-256 key and save it encrypted with a password.

    The key is encrypted directly in memory — it NEVER exists
    as plaintext on disk.

    Returns the raw AES key bytes (for immediate use).
    """
    aes_key = os.urandom(AES_KEY_SIZE)

    try:
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        derived = _derive_key(password, salt)

        header = MAGIC_PASSWORD + salt + nonce
        aesgcm = AESGCM(derived)
        ciphertext = aesgcm.encrypt(nonce, aes_key, header)

        enc_path = f"{key_name}.enc"
        if os.path.exists(enc_path):
            raise FileExistsError(f"Key file already exists: {enc_path}")

        with open(enc_path, "wb") as f:
            f.write(header + ciphertext)

        _set_restrictive_permissions(enc_path)
        return aes_key

    except (PermissionError, OSError) as e:
        raise IOError(f"File system error: {e}")


def decrypt_key_file(key_file: str, password: str) -> bytes:
    """Decrypt an encrypted AES key file and return the raw key bytes."""
    if not os.path.isfile(key_file):
        raise FileNotFoundError(f"Key file not found: {key_file}")

    try:
        with open(key_file, "rb") as f:
            raw = f.read()

        if len(raw) < MIN_KEY_FILE:
            raise ValueError("Key file corrupted or truncated")

        magic = raw[:4]
        if magic != MAGIC_PASSWORD:
            raise ValueError("Invalid key file format")

        salt = raw[4:4 + SALT_SIZE]
        nonce = raw[4 + SALT_SIZE:4 + SALT_SIZE + NONCE_SIZE]
        ciphertext = raw[4 + SALT_SIZE + NONCE_SIZE:]
        header = raw[:4 + SALT_SIZE + NONCE_SIZE]

        derived = _derive_key(password, salt)
        aesgcm = AESGCM(derived)
        aes_key = aesgcm.decrypt(nonce, ciphertext, header)

        if len(aes_key) != AES_KEY_SIZE:
            raise ValueError(
                f"Decrypted key has invalid size ({len(aes_key)} bytes) "
                f"— file may be corrupted"
            )

        return aes_key

    except InvalidTag:
        raise ValueError("Key decryption failed: wrong password")

    except (FileNotFoundError, PermissionError, OSError) as e:
        raise IOError(f"Key file error: {e}")
