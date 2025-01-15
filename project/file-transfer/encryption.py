from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os

# AES encryption function
def encrypt_file(file_name, key):
    cipher = AES.new(key, AES.MODE_GCM)
    with open(file_name, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    enc_file_name = file_name + '.enc'
    with open(enc_file_name, 'wb') as enc_file:
        for x in (cipher.nonce, tag, ciphertext):
            enc_file.write(x)
    return enc_file_name

# AES decryption function
def decrypt_file(file_name, key):
    with open(file_name, 'rb') as enc_file:
        nonce, tag, ciphertext = [enc_file.read(x) for x in (16, 16, -1)]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    dec_file_name = file_name.replace('.enc', '')
    with open(dec_file_name, 'wb') as dec_file:
        dec_file.write(plaintext)
    return dec_file_name

# Generate SHA-256 hash of the file
def generate_file_hash(file_name):
    sha256_hash = hashlib.sha256()
    with open(file_name, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

