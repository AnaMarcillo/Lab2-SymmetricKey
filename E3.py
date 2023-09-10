from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import binascii
import base64

cipher_base64 = '5I71KpfT6RdM/xhUJ5IKCQ=='
password = '123456'

# Decode the Base64 encoded ciphertext to bytes
ciphertext = base64.b64decode(cipher_base64)

key = hashlib.sha256(password.encode()).digest()[:32]  # AES-256 key is 32 bytes long

def decrypt(ciphertext, key, mode):
    method = algorithms.AES(key)
    cipher = Cipher(method, mode, default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data)
    unpadded_data += unpadder.finalize()
    return unpadded_data

plaintext = decrypt(ciphertext, key, modes.ECB())
plaintext = unpad(plaintext)

print("Decrypted text:", plaintext.decode())
