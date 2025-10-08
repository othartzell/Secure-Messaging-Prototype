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

# Task 2: Diffie-Hellman Exchange - Develop a funcion (or functions) to implement the steps involved in the key exchange

class DiffieHellman:
    # Generating private value a or b and public value g^a or b mod p
    def __init__(self, p=None, g=None):
        # If no p and g are provided, generate new parameters
        if p is None or g is None:
            self.parameters = dh.generate_parameters(generator=2, key_size=512)
            pn = self.parameters.parameter_numbers()
            self.p = pn.p
            self.g = pn.g

            # Logic for shared file for p and g
            # with open("parameters.txt", "w") as f:
            #     f.write(f"{self.p}\n{self.g}\n")
        else:
            pn = dh.DHParameterNumbers(p, g)
            self.parameters = pn.parameters()
            self.p = p
            self.g = g

        # Generate private and public keys
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

        self.signature = DigitalSignature()

    # Return p and g
    def get_params(self):
        return self.p, self.g

    # Returning g^a or b mod p
    def get_public_value(self):
        return self.public_key.public_numbers().y
    
    # Serializing DH public value (g^(a or b) mod p) into a byte string for the digital signature
    def serialize_public_value(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    # Deserialize received bytes back into a DH public key object
    def deserialize_public_value(self, serialized_bytes):
        return serialization.load_der_public_key(serialized_bytes)
    
    # Signing g^x mod p using DigitalSignature class
    def sign_public(self):
        return self.signature.sign_message(self.serialize_public_value())
    
    # Verifying digital signature of senders DH public value using senders RSA public key
    def verify_other_public(self, other_bytes: bytes, signature: bytes, other_rsa_public):
        return self.signature.verify_signature(other_bytes, signature, other_rsa_public)
    
    # Computing the shared secret using the others public key
    def compute_shared_secret(self, peer_public_key):
        secret_bytes = self.private_key.exchange(peer_public_key)
        return int.from_bytes(secret_bytes, byteorder='big')
    
    # Getting the peer key
    def get_peer_key(self, y):
        pn = self.parameters.parameter_numbers()
        public_numbers = dh.DHPublicNumbers(y, pn)
        return public_numbers.public_key()