# Owen Hartzell ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# REFERENCES
#   Key Derivation Functions - https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
#   HKDF -https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.hkdf.HKDF

# Imports
from cryptography.hazmat.primitives import hashes

# Task 3: Encryption Key Derivation

class KDF:
    # Function for key deriviation, takes in shared secret and hashing iterations
    @staticmethod
    def derive_key(shared_secret: int, iterations: int):
        # Converting shared secret to bytes
        byte_length = (shared_secret.bit_length() + 7) // 8
        current_hash = shared_secret.to_bytes(byte_length, 'big')

        # Performing hashing
        for i in range(iterations):
            digest = hashes.Hash(hashes.SHA256())
            digest.update(current_hash)
            current_hash = digest.finalize()

        return current_hash