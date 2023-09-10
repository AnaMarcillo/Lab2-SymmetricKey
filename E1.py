from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import binascii

# Function to decrypt ciphertext using AES ECB and CMS padding
def aes_decrypt_ecb_cms(ciphertext, key):
    # Generate the AES key by hashing the provided key
    key = hashlib.sha256(key.encode()).digest()  
    method = algorithms.AES(key)     # Initialize AES cipher with ECB mode
    cipher = Cipher(method, modes.ECB(), default_backend())   
    # Initialize AES decryptor
    decryptor = cipher.decryptor()   
    # Decrypt ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()   
    # Unpad the plaintext using PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_plaintext = unpadder.update(plaintext) + unpadder.finalize()   
    return unpadded_plaintext

ciphertext_hex = 'b436bd84d16db330359edebf49725c62'  # Replace with the ciphertext
encryption_key = 'hello'  # Replace with the encryption key
# Convert the hexadecimal ciphertext to bytes
ciphertext = binascii.unhexlify(ciphertext_hex)
# Decrypt the ciphertext
decrypted_plaintext = aes_decrypt_ecb_cms(ciphertext, encryption_key)
print("Decrypted Plaintext:", decrypted_plaintext.decode())
