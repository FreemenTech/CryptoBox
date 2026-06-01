"""
CryptoBox v2.0 — Security constants and file format specifications.

File formats:
    Password mode (CBX1):  MAGIC(4) | SALT(16) | NONCE(12) | CIPHERTEXT+TAG(N+16)
    AES key mode  (CBX2):  MAGIC(4) | NONCE(12) | CIPHERTEXT+TAG(N+16)
    Key file (.enc):       Uses CBX1 format (password-protected)

AAD (Additional Authenticated Data):
    Always set to the full header (everything before ciphertext),
    so magic, salt, and nonce are tamper-proof.
"""

__version__ = "2.0.0"

# ── Magic headers ──────────────────────────────────────────────
MAGIC_PASSWORD = b"CBX1"  # password-based encryption
MAGIC_AES_KEY = b"CBX2"   # AES key-based encryption

# ── Cryptographic parameters ──────────────────────────────────
PBKDF2_ITERATIONS = 600_000  # OWASP 2023 recommendation for SHA-256
AES_KEY_SIZE = 32            # 256 bits
SALT_SIZE = 16               # 128 bits
NONCE_SIZE = 12              # 96 bits — required by GCM
GCM_TAG_SIZE = 16            # 128 bits — appended to ciphertext by AESGCM

# ── Password policy ───────────────────────────────────────────
MIN_PASSWORD_LENGTH = 8

# ── File safety limits ────────────────────────────────────────
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB — prevents OOM

# ── Minimum valid encrypted file sizes ────────────────────────
# Password: MAGIC(4) + SALT(16) + NONCE(12) + TAG(16) = 48
MIN_PASSWORD_FILE = (
    len(MAGIC_PASSWORD) + SALT_SIZE + NONCE_SIZE + GCM_TAG_SIZE
)
# AES key: MAGIC(4) + NONCE(12) + TAG(16) = 32
MIN_AES_FILE = (
    len(MAGIC_AES_KEY) + NONCE_SIZE + GCM_TAG_SIZE
)
# Key file reuses password format
MIN_KEY_FILE = MIN_PASSWORD_FILE
