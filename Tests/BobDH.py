# Owen Hartzell 801188721 ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# Logic for user Bob to test DiffieHellman.py

from DiffieHellman import DiffieHellman
from cryptography.hazmat.primitives import serialization

# Getting parameters p and g from console
print("\n=== Bob ===")
p_str = input("Paste the value for p from Alice's terminal: ")
g_str = input("Paste the value for g from Alice's terminal: ")

# Converting string to int
p = int(p_str.strip())
g = int(g_str.strip())

# Create Bob
bob = DiffieHellman(p, g)
bob_pub = bob.get_public_value()
print(f"Bob's public value (g^b mod p): {bob_pub}")

# Sign and serialize DH public value
bob_serialized = bob.serialize_public_value()
bob_signature = bob.sign_public()

print(f"\nBob's DH public value (hex):\n{bob_serialized.hex()}")
print(f"\nBob's signature (hex):\n{bob_signature.hex()}")

# Print Bob's RSA public key in hex for Alice to use
bob_rsa_pub_bytes = bob.signature.public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(f"\nBob's RSA public key (hex):\n{bob_rsa_pub_bytes.hex()}")

# Receive Alice's DH serialized value, signature, and RSA public key
alice_serialized_hex = input("\nPaste Alice's DH public value (hex): ")
alice_signature_hex = input("Paste Alice's signature (hex): ")
alice_rsa_pub_hex = input("Paste Alice's RSA public key (hex): ")

alice_serialized = bytes.fromhex(alice_serialized_hex)
alice_signature = bytes.fromhex(alice_signature_hex)
alice_rsa_pub_bytes = bytes.fromhex(alice_rsa_pub_hex)

# Deserialize Alice's DH and RSA keys
alice_pub_key = bob.deserialize_public_value(alice_serialized)
alice_rsa_pub = serialization.load_der_public_key(alice_rsa_pub_bytes)

# Verify Alice's signature
verified = bob.verify_other_public(alice_serialized, alice_signature, alice_rsa_pub)
print(f"\nSignature verified? {verified}")

# Compute shared secret
shared_secret = bob.compute_shared_secret(alice_pub_key)
print(f"\nBob's shared secret: {shared_secret}")