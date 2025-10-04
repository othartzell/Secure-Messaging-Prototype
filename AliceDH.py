# Owen Hartzell 801188721 ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# Logic for user Alice to test DiffieHellman.py

from DiffieHellman import DiffieHellman
from cryptography.hazmat.primitives import serialization

# Create Alice
alice = DiffieHellman()
alice_pub = alice.get_public_value()
p, g = alice.get_params()

print("\n=== Alice ===")
print(f"p: {p}")
print(f"g: {g}")
print(f"Alice's public value (g^a mod p): {alice_pub}")

# Sign and serialize DH public value
alice_serialized = alice.serialize_public_value()
alice_signature = alice.sign_public()

print(f"Alice's DH public value (hex): {alice_serialized.hex()}")
print(f"Alice's signature (hex): {alice_signature.hex()}")

# Print Alice's RSA public key in hex for Bob to use
alice_rsa_pub_bytes = alice.signature.public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(f"Alice's RSA public key (hex): {alice_rsa_pub_bytes.hex()}")

# Receive Bob's DH serialized value, signature, and RSA public key
bob_serialized_hex = input("Paste Bob's DH public value (hex): ")
bob_signature_hex = input("Paste Bob's signature (hex): ")
bob_rsa_pub_hex = input("Paste Bob's RSA public key (hex): ")

bob_serialized = bytes.fromhex(bob_serialized_hex)
bob_signature = bytes.fromhex(bob_signature_hex)
bob_rsa_pub_bytes = bytes.fromhex(bob_rsa_pub_hex)

# Deserialize Bob's DH and RSA keys
bob_pub_key = alice.deserialize_public_value(bob_serialized)
bob_rsa_pub = serialization.load_der_public_key(bob_rsa_pub_bytes)

# Verify Bob's signature
verified = alice.verify_other_public(bob_serialized, bob_signature, bob_rsa_pub)
print(f"Signature verified? {verified}")

# Compute shared secret
shared_secret = alice.compute_shared_secret(bob_pub_key)
print(f"Alice's shared secret: {shared_secret}")
