from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

import hashlib
import binascii

ciphertext_hex = '6ee95415aca2b33c'
password = 'ankle'

ciphertext = binascii.unhexlify(ciphertext_hex)

key = hashlib.sha256(password.encode()).digest()[:16]

def decrypt(ciphertext, key, mode):
    method = algorithms.TripleDES(key)
    cipher = Cipher(method, mode, default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def unpad(data):
    unpadder = padding.PKCS7(64).unpadder()
    unpadded_data = unpadder.update(data)
    unpadded_data += unpadder.finalize()
    return unpadded_data

plaintext = decrypt(ciphertext, key, modes.ECB())
plaintext = unpad(plaintext)

print("Decrypted text:", plaintext.decode())
