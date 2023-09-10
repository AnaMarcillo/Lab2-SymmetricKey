# Import necessary modules from the cryptography library
import sys 
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import binascii

# Function to perform AES encryption and return the ciphertext
def aes_encrypt(plaintext, key):
    # Function to pad data
    def pad(data, size=128):
        padder = padding.PKCS7(size).padder()
        padded_data = padder.update(data.encode())
        padded_data += padder.finalize()
        return padded_data

    # Generate the key from the provided key string
    key = hashlib.sha256(key.encode()).digest()

    # Pad the plaintext
    plaintext = pad(plaintext)

    # Encrypt the padded plaintext using ECB mode and return the ciphertext
    method = algorithms.AES(key)
    cipher = Cipher(method, modes.ECB(), default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

if __name__ == "__main__":
    # Check if the correct number of command-line arguments are provided
    if len(sys.argv) != 3:
        print("Usage: python d_01.py <plaintext> <key>")
        sys.exit(1)
    plaintext = sys.argv[1]
    key = sys.argv[2]
    ciphertext = aes_encrypt(plaintext, key)
    print("Ciphertext: {} ({})".format(binascii.hexlify(bytearray(ciphertext[:2])).decode(), binascii.hexlify(bytearray(ciphertext[2:])).decode()))

