import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from config import config

def encrypt(key: str, plaintext: str) \
        -> str:
    """
    Encrypts plaintext with a config['bytes']-byte key using the AES protocol
    with cipher block chaining (CBC).
    
    Propagating cipher block chaining (PCBC) was considered, but
    decided against because of the issue mentioned here:
    https://web.archive.org/web/20090612060426/http://dsns.csie.nctu.edu.tw/research/crypto/HTML/PDF/C89/35.PDF
    
    In short, due to the nature of PCBC, swapped ciphertexts and all ciphertexts
    in between would decrypt incorrectly, but subsequent ciphertexts would
    decrypt correctly, and this behaviour is undesireable. 
    """
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key.encode('utf-8')), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(config['bytes'] * 8).padder()
    
    plainbytes = plaintext.encode('utf-8') # plaintext -> bytes
    data = padder.update(plainbytes) + padder.finalize() # pad to n * cipher bytes
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    return iv + ciphertext

def decrypt(key: str, encrypted_data: str) \
        -> str:
    """
    Decrypts plaintext with a config['bytes']-byte key using the AES protocol
    with cipher block chaining (CBC).
    """
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    cipher = Cipher(algorithms.AES(key.encode('utf-8')), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    
    data = decryptor.update(ciphertext) + decryptor.finalize()
    plainbytes = unpadder.update(data) + unpadder.finalize()
    
    return plainbytes.decode('utf-8')
