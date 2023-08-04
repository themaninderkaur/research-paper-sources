import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def generate_blowfish_key():
    return os.urandom(16)  # Generate a random 16-byte (128-bit) key

def blowfish_encrypt(file_path, key):
    chunk_size = 64 * 1024
    output_file = file_path + '.enc'

    backend = default_backend()

    with open(file_path, 'rb') as file:
        data = file.read()

    # Generate a random initialization vector (IV)
    iv = os.urandom(8)

    # Create a Blowfish cipher with CBC mode
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=backend)

    # Create an encryptor
    encryptor = cipher.encryptor()

    # Pad the data to a multiple of the block size
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write the IV and encrypted data to the output file
    with open(output_file, 'wb') as encrypted_file:
        encrypted_file.write(iv)
        encrypted_file.write(encrypted_data)

    return output_file

def blowfish_decrypt(file_path, key):
    chunk_size = 64 * 1024
    output_file = file_path[:-4]  # Remove the '.enc' extension

    backend = default_backend()

    with open(file_path, 'rb') as encrypted_file:
        iv = encrypted_file.read(8)  # Read the IV from the beginning of the encrypted file
        encrypted_data = encrypted_file.read()

    # Create a Blowfish cipher with CBC mode
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=backend)

    # Create a decryptor
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(64).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Write the decrypted data to the output file
    with open(output_file, 'wb') as decrypted_file:
        decrypted_file.write(unpadded_data)

    return output_file

# Generate Blowfish key
key = generate_blowfish_key()

# Set the file path of the file you want to encrypt and decrypt
file_path = '/Users/maninderkaur/Desktop/sources for paper/lorem ipsum/book.rtf'

# Encrypt the file and measure the time taken
start_time = time.time()
encrypted_file_path = blowfish_encrypt(file_path, key)
encryption_time = time.time() - start_time

# Decrypt the file and measure the time taken
start_time = time.time()
decrypted_file_path = blowfish_decrypt(encrypted_file_path, key)
decryption_time = time.time() - start_time

print(f"Encryption time: {encryption_time} seconds")
print(f"Decryption time: {decryption_time} seconds")



