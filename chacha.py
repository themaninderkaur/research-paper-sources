import time
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher  # Add this line
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding



def generate_chacha20_key():
    password = os.urandom(16)  # Replace with your password
    salt = os.urandom(16)  # Replace with a unique salt

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

def encrypt_file(file_path, key):
    chunk_size = 64 * 1024
    output_file = file_path + '.enc'

    backend = default_backend()

    with open(file_path, 'rb') as file:
        with open(output_file, 'wb') as encrypted_file:
            nonce = os.urandom(16)  # Use a secure random nonce for each encryption
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

            encryptor = cipher.encryptor()
            encrypted_file.write(nonce)

            while True:
                chunk = file.read(chunk_size)
                if len(chunk) == 0:
                    break
                encrypted_chunk = encryptor.update(chunk)
                encrypted_file.write(encrypted_chunk)

    return output_file

def decrypt_file(file_path, key):
    chunk_size = 64 * 1024
    output_file = file_path[:-4]  # Remove the '.enc' extension

    backend = default_backend()

    with open(file_path, 'rb') as encrypted_file:
        nonce = encrypted_file.read(16)  # Read the nonce from the beginning of the encrypted file
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

        with open(output_file, 'wb') as decrypted_file:
            decryptor = cipher.decryptor()

            while True:
                chunk = encrypted_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                decrypted_chunk = decryptor.update(chunk)
                decrypted_file.write(decrypted_chunk)

    return output_file

# Generate ChaCha20 key
key = generate_chacha20_key()

# Set the file path of the file you want to encrypt and decrypt
file_path = '/Users/maninderkaur/Desktop/sources for paper/lorem ipsum/book.rtf'

# Encrypt the file and measure the time taken
start_time = time.time()
encrypted_file_path = encrypt_file(file_path, key)
encryption_time = time.time() - start_time

# Decrypt the file and measure the time taken
start_time = time.time()
decrypted_file_path = decrypt_file(encrypted_file_path, key)
decryption_time = time.time() - start_time

print(f"Encryption time: {encryption_time} seconds")
print(f"Decryption time: {decryption_time} seconds")
