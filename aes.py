import time
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(file_path, key):
    chunk_size = 64 * 1024
    output_file = file_path + '.enc'

    backend = default_backend()
    iv = b'\x00' * 16  # You should use a secure random IV in practice

    with open(file_path, 'rb') as file:
        with open(output_file, 'wb') as encrypted_file:
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
            encryptor = cipher.encryptor()

            while True:
                chunk = file.read(chunk_size)
                if len(chunk) == 0:
                    break

                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(chunk) + padder.finalize()
                encrypted_chunk = encryptor.update(padded_data)
                encrypted_file.write(encrypted_chunk)

    return output_file

def decrypt_file(file_path, key):
    chunk_size = 64 * 1024
    output_file = file_path[:-4]  # Remove the '.enc' extension

    backend = default_backend()
    iv = b'\x00' * 16  # You should use the same IV used during encryption

    with open(file_path, 'rb') as encrypted_file:
        with open(output_file, 'wb') as decrypted_file:
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
            decryptor = cipher.decryptor()

            while True:
                chunk = encrypted_file.read(chunk_size)
                if len(chunk) == 0:
                    break

                decrypted_chunk = decryptor.update(chunk)
                unpadder = padding.PKCS7(128).unpadder()
                unpadded_data = unpadder.update(decrypted_chunk) + unpadder.finalize()
                decrypted_file.write(unpadded_data)

    return output_file

# Set your encryption key (should be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256, respectively)
key = b'Sixteen byte key'

# Specify the file path of the file you want to encrypt and decrypt
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
