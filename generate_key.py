import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import  serialization 
from password_encryption import encrypt_file_password


#==================================================
              #GENERATE SYMMETRIC KEY
#==================================================

def generate_aes_key(key_name,password):
    try:
        aes_key = os.urandom(32) #256b bits

        key_path = f"{key_name}.key"
        enc_path = f"{key_name}.enc"


        #Save aes key 
        with open(key_path , "wb") as f : #wb is used to write binary
            f.write(aes_key)
        
        #Protect key file 
        
        encrypt_file_password(key_path, enc_path, password )
        os.remove(key_path)

        return aes_key

    except (PermissionError, OSError) as e:
        raise IOError(f"File system error while generating AES key: {e}")

    except ValueError as e:
        raise RuntimeError(f"AES key protection failed: {e}")
   