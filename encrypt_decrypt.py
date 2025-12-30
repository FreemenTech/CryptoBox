import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag



#===============================================
                #ENCRYPT FILE
#===============================================

def encrypt_file(input_file, output_file, aes_key):
    try:

        with open(input_file , "rb") as f:
            data = f.read()
        
        nonce = os.urandom(12) #recommended for GCM
        aesgcm = AESGCM(aes_key)

        ciphertext = aesgcm.encrypt(nonce, data, None)

        #File encrypted format : nonce + data
        with open(output_file, "wb") as f :
            f.write(nonce + ciphertext)

    except (PermissionError, OSError) as e:
        raise IOError(f"File access error: {e}")

    except ValueError as e:
        raise RuntimeError(f"Encryption failed: {e}")


#===============================================
                #DECRYPT FILE
#===============================================

def decrypt_file(input_file,output_file, key ):
    try:

        with open(input_file, "rb") as f:
            content= f.read()

        if len(content) < 13:
            raise ValueError("File corrupted or invalid")

        #1. Extract parts
        nonce = content[:12] #12 first bytes
        ciphertext = content[12:] #everything else

        # 2. Initialize AESGCM
        aesgcm = AESGCM(key)

        # 3. Decrypt (automatically checks the tag)
        data = aesgcm.decrypt(nonce,ciphertext,None)

        # 4. Save
        with  open(output_file, "wb") as f:
            f.write(data)
        
    except InvalidTag:
        raise ValueError("Decryption failed: wrong key or corrupted file")

    except (FileNotFoundError, PermissionError, OSError) as e:
        raise IOError(f"File access error: {e}")

    except ValueError as e:
        raise RuntimeError(f"Decryption error: {e}")
    


    