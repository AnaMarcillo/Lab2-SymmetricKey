from Crypto.Cipher import DES
import hashlib
import binascii
import Padding

def des_encrypt(plaintext, password):
    key = hashlib.sha256(password.encode()).digest()[:8]
    plaintext = Padding.appendPadding(plaintext, blocksize=Padding.DES_blocksize, mode='CMS')
    encobj = DES.new(key, DES.MODE_ECB)
    ciphertext = encobj.encrypt(plaintext.encode())
    return binascii.hexlify(bytearray(ciphertext)).decode()

cipher = input('Enter cipher: ')
password = input('Enter password: ')

# Encrypt
encrypted_text = des_encrypt(cipher, password)
print("Cipher (ECB):", encrypted_text)
