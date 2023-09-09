# Import necessary modules from the cryptography library
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

import hashlib
import binascii

# Modify these values with your data and password
val = 'your_data_here'
password = 'your_password_here'

plaintext = val

# Function to encrypt plaintext using AES
def encrypt(plaintext, key, mode):
    method = algorithms.AES(key)
    cipher = Cipher(method, mode, default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    return ct

# Function to decrypt ciphertext using AES
def decrypt(ciphertext, key, mode):
    method = algorithms.AES(key)
    cipher = Cipher(method, mode, default_backend())
    decryptor = cipher.decryptor()
    pl = decryptor.update(ciphertext) + decryptor.finalize()
    return pl

# Function to pad data with PKCS7 padding
def pad(data, size=128):
    padder = padding.PKCS7(size).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data

# Function to unpad data with PKCS7 padding
def unpad(data, size=128):
    padder = padding.PKCS7(size).unpadder()
    unpadded_data = padder.update(data)
    unpadded_data += padder.finalize()
    return unpadded_data

# Generate the AES key by hashing the password
key = hashlib.sha256(password.encode()).digest()

# Print the original plaintext before encryption
print("Before padding: ", plaintext)

# Pad the plaintext with PKCS7 padding
plaintext = pad(plaintext.encode())

# Print the padded plaintext in hexadecimal format
print("After padding (CMS): ", binascii.hexlify(bytearray(plaintext)))

# Encrypt the plaintext using AES encryption in ECB mode
ciphertext = encrypt(plaintext, key, modes.ECB())

# Print the ciphertext in hexadecimal format
print("Cipher (ECB): ", binascii.hexlify(bytearray(ciphertext)))

# Decrypt the ciphertext back to plaintext
plaintext = decrypt(ciphertext, key, modes.ECB())

# Unpad the plaintext to remove PKCS7 padding
plaintext = unpad(plaintext)

# Print the decrypted plaintext
print("  decrypt: ", plaintext.decode())

