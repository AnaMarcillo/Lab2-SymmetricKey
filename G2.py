"""
a.	8d1cc8bdf6da = orange
b.	911adbb2e6dda57cdaad = strawberry
c.	8907deba = kiwi

"""
from Crypto.Cipher import ARC4
import hashlib
# Define a function to perform RC4 decryption
def rc4_decrypt(key, ciphertext_hex):
    
    cipher = ARC4.new(key)  # Create an ARC4 cipher object with the provided key
    ciphertext_bytes = bytes.fromhex(ciphertext_hex) # Convert the hexadecimal ciphertext to bytes 
    decrypted_bytes = cipher.decrypt(ciphertext_bytes) # Decrypt the ciphertext  
    return decrypted_bytes.decode('utf-8') # Decode the decrypted bytes as a UTF-8 string
def main():
    keyname = "napier"
    ciphertext_hex = "8907deba"   
    key = hashlib.sha256(keyname.encode()).digest() # Hash the key name using SHA-256 to derive the actual key 
    decrypted_text = rc4_decrypt(key, ciphertext_hex) # Decrypt the ciphertext using the key and print the results
    print("Ciphertext (Hexadecimal):", ciphertext_hex)
    print("Decrypted plaintext:", decrypted_text)
if __name__ == "__main__":
    main()
