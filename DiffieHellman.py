# Owen Hartzell 801188721 ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# REFRENCES
# Cryptography library manuals:
    # Diffie-Hellman key exchange - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/
    # RSA - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
    # Message digests (Hashing) - https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/#cryptography.hazmat.primitives.hashes.Hash

# Imports
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from DigitalSignature import DigitalSignature

class DiffieHellman:
    def __init__(self, parameters=None):
        # Generating g and p for DH
        if parameters is None:
            parameters = dh.generate_parameters(generator=2, key_size=2048)
        self.parameters = parameters

        # Generating private value a or b and public value g^(a or b) mod p
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

        # Generating keys for digital signature of public value
        self.signature = DigitalSignature()

    # Serializing DH public value (g^(a or b) mod p) into a byte string for the digital signature
    def get_public_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    # Signing g^x mod p using DigitalSignature class
    def sign_public(self):
        return self.signature.sign_message(self.get_public_bytes())
    
    # Verifying digital signature of senders DH public value using senders RSA public key
    def verify_other_public(self, other_bytes: bytes, signature: bytes, other_rsa_public):
        return self.signature.verify_signature(other_bytes, signature, other_rsa_public)
    
    # Computing shared secret (g^(ab) mod p) using senders DH public value
    def shared_secret(self, other_public_key):
        return self.private_key.exchange(other_public_key)