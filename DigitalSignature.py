# Owen Hartzell 801188721 ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# REFRENCES
# Cryptography library manuals:
    # Diffie-Hellman key exchange - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/
    # RSA - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
    # Message digests (Hashing) - https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/#cryptography.hazmat.primitives.hashes.Hash

# Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

#TASK 1: Digital Signature - Build a digital signature mechanism

# Wrapper class for digital signature functions
class DigitalSignature:

    # Function for key generation
    def __init__(self, key_size=2048):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        self.public_key = self.private_key.public_key()

    # Function for hashing (Hash values of messages are signed)
    def hash_message(self, message: bytes):
        digest = hashes.Hash(hashes.SHA256()) 
        digest.update(message) 
        return digest.finalize()
    
    # Function to sign a message
    def sign_message(self, message: bytes):
        return self.private_key.sign(
            self.hash_message(message),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    # Function to verify a signature
    def verify_signature(self, message: bytes, signature: bytes, public_key):
        try:
            public_key.verify(
                signature,
                self.hash_message(message),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return 1
        except InvalidSignature:
            return 0