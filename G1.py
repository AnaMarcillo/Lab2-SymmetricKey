#Develop an application in Python to implement the ChaCha20 stream cipher. 
"""
a.	e47a2bfe646a = orange
b.	ea783afc66   = apple
c. e96924f16d6e  = banana

""" 
from Crypto.Cipher import ChaCha20
import hashlib
def chacha20_decrypt(key, nonce, ciphertext):  
    cipher = ChaCha20.new(key=key, nonce=nonce)      # Create a ChaCha20 cipher object with the provided key and nonce 
    plaintext = cipher.decrypt(ciphertext) # Decrypt the ciphertext using the cipher
    return plaintext.decode() # Convert the decrypted bytes to a string (assuming it's text)  
def main():
    keyname = "qwerty"
    ciphertext_hex = "e96924f16d6e"
    key = hashlib.sha256(keyname.encode()).digest()     # Hash the keyname using SHA-256 to derive the actual encryption key   
    nonce = b'\x00' * 8 # Define the nonce as 8 bytes filled with zeros
    # Convert the ciphertext from hexadecimal to bytes
    ciphertext = bytes.fromhex(ciphertext_hex) 
    decrypted_text = chacha20_decrypt(key, nonce, ciphertext) # Decrypt the ciphertext using ChaCha20 and the provided key and nonce
    print("Ciphertext:", ciphertext_hex)
    print("Decrypted plaintext:", decrypted_text)

if __name__ == "__main__":
    main()

