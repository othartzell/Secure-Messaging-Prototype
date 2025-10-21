# Owen Hartzell ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# REFERENCES
    # Symmetric encryption - https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.Cipher
    # Symmetric padding - https://cryptography.io/en/latest/hazmat/primitives/padding/
    # CBC Mode - https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#module-cryptography.hazmat.primitives.ciphers.modes

# Imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hmac, hashes
from PRNG import PRNG
import secrets

# Task 5: Secure Message Exchange

class SecureMessageExchange:
    # Initializing user and key with KDF from task 3
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("INVALID KEY")
        self.key = key

    # Function for Cipher Block Chaining Mode symmetric encryption
    def sym_enc(self, plaintext: bytes, iv: bytes) -> bytes:
        # Padding plaintext input to fit block size
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(plaintext) + padder.finalize()

        # Creating ciphertext using AES CBC mode
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        return ciphertext
    
    # Function for Cipher Block Chaining Mode symmetric decryption
    def sym_dec(self, ciphertext: bytes, iv: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_text = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpadding the decrypted message to get plaintext
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_text) + unpadder.finalize()
        return plaintext
    
    # Function for computing HMAC
    def compute_hmac(self, data: bytes) -> bytes:
        h = hmac.HMAC(self.key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    # Function for authenticated encryption using the "Encrypt then MAC" scheme
    def encrypt(self, plaintext: bytes, prng: PRNG) -> bytes:
        # Generate IV using PRNG.py
        iv = prng.generate(16)

        # Encrypt the plaintext
        ciphertext = self.sym_enc(plaintext, iv)

        # Compute the HMAC on the ciphertext
        hmac = self.compute_hmac(ciphertext)

        # Return the concatenated IV, Ciphertext, and HMAC
        return iv + ciphertext + hmac

    # Function for authenticated decryption, verifies integrity using mac before decrypting
    def decrypt(self, message: bytes) -> bytes:
        # Splitting concatenated message for IV, Ciphertext, and HMAC
        iv = message[:16]
        recieved_mac = message[-32:]
        ciphertext = message[16:-32]

        # Intgegrity check of HMAC before decrypting, raising error if the check fails
        computed_mac = self.compute_hmac(ciphertext)
        if not secrets.compare_digest(recieved_mac, computed_mac):
            raise ValueError("INTEGRITY CHECK FAILED: INVALID MAC")
        
        # Decrypting if integrity check passed
        plaintext = self.sym_dec(ciphertext, iv)
        return plaintext