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
    # Generating private value a or b and public value g^a or b mod p
    def __init__(self, p=None, g=None):
        # If no p and g are provided, generate new parameters
        if p is None or g is None:
            self.parameters = dh.generate_parameters(generator=2, key_size=512)
            pn = self.parameters.parameter_numbers()
            self.p = pn.p
            self.g = pn.g

            with open("parameters.txt", "w") as f:
                f.write(f"{self.p}\n{self.g}\n")
        else:
            pn = dh.DHParameterNumbers(p, g)
            self.parameters = pn.parameters()
            self.p = p
            self.g = g

        # Generate private and public keys
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        
    def get_params(self):
        return self.p, self.g

    # Returning g^a or b mod p
    def get_public_value(self):
        return self.public_key.public_numbers().y
    
    # Computing the shared secret using the others public key
    def compute_shared_secret(self, peer_public_key):
        secret_bytes = self.private_key.exchange(peer_public_key)
        return int.from_bytes(secret_bytes, byteorder='big')
    
    def get_peer_key(self, y):
        pn = self.parameters.parameter_numbers()
        public_numbers = dh.DHPublicNumbers(y, pn)
        return public_numbers.public_key()