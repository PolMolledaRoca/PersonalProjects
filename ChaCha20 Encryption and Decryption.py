from Crypto.Cipher import ChaCha20

def main():
    # Define the encryption key and nonce
    encryption_key = b'z\xe8~"\xcayW\x14g\x18+\x1c+\xf9\x80\x06P\x9ej\x888\xb4G\xdf\xe4\xc50,\x8dY\x80\x19'
    nonce = b'\xd6\x7f6\xc7\xe8i*\xa4'
    plaintext_message = b"This is a secret message I want to encrypt."

    # Encrypt the message
    cipher = ChaCha20.new(key=encryption_key, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext_message)

    print("Encrypted Message:", ciphertext)

    # Decrypt the message
    # Create a new cipher object for decryption using the same key and nonce
    cipher_dec = ChaCha20.new(key=encryption_key, nonce=nonce)
    decrypted_message = cipher_dec.decrypt(ciphertext)

    print("Decrypted Message:", decrypted_message.decode('utf-8'))  # Decode bytes to string

if __name__ == "__main__":
    main()
