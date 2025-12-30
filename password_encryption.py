import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rich import print
from cryptography.exceptions import InvalidTag


MAGIC = b"CBX1" #cryptobox v1

def derive_key(password: str , salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  #AES-256
        salt=salt,
        iterations=300_000, #against brute-force  
    )
    return kdf.derive(password.encode())



def encrypt_file_password(input_file, output_file, password):
    try:
        salt = os.urandom(16)
        nonce = os.urandom(12)

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        with open(input_file, "rb") as f:
            data = f.read()

        ciphertext = aesgcm.encrypt(nonce, data, None)

        with open(output_file, "wb") as f:
            f.write(MAGIC + salt + nonce + ciphertext)
        
        

    except (PermissionError, OSError) as e:
        raise IOError(f"File system error: {e}")

    except ValueError as e:
        raise RuntimeError(f"Encryption failed: {e}")






def decrypt_file_password(input_file, output_file, password):
    try:
        with open(input_file, "rb") as f:
            raw = f.read()

        if len(raw) < 32:
            raise ValueError("File corrupted or incomplete")

        if raw[:4] != MAGIC:
            raise ValueError("Invalid file format. Use the correct decryption mode.")

        salt = raw[4:20]
        nonce = raw[20:32]
        ciphertext = raw[32:]

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        with open(output_file, "wb") as f:
            f.write(plaintext)

    except InvalidTag:
        raise ValueError("Decryption failed: wrong password or corrupted file")

    except (FileNotFoundError, PermissionError, OSError) as e:
        raise IOError(f"File system error: {e}")




        




def decrypt_key_file(key_name, password):
    try:
        with open(key_name, "rb") as f:
            raw = f.read()

        if len(raw) < 32:
            raise ValueError("Key file corrupted")

        if raw[:4] != MAGIC:
            raise ValueError("Invalid key file format")

        salt = raw[4:20]
        nonce = raw[20:32]
        ciphertext = raw[32:]

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext

    except InvalidTag:
        raise ValueError("Key decryption failed: wrong password")

    except (FileNotFoundError, PermissionError, OSError) as e:
        raise IOError(f"Key file error: {e}")
            


