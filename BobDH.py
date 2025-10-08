# Owen Hartzell 801188721 ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# Logic for user Bob to test DiffieHellman.py

from DiffieHellman import DiffieHellman
from cryptography.hazmat.primitives import serialization
import base64

# Getting parameters p and g from a shared file
# with open("parameters.txt", "r") as f:
#     lines = f.readlines()
#     p = int(lines[0].strip())
#     g = int(lines[1].strip())

# Create Bob
# bob = DiffieHellman(p, g)
# bob_pub = bob.get_public_value()

# print("\n=== Bob ===")
# print(f"p: {p}")
# print(f"g: {g}")
# print(f"Bob's public value (g^b mod p): {bob_pub}")

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
print(f"Bob's public value (g^a mod p): {bob_pub}")

# Sign and serialize DH public value
bob_serialized = bob.serialize_public_value()
bob_signature = bob.sign_public()

print("\n=== Bob's DH public value (base64) ===")
print(f"\n{base64.b64encode(bob_serialized).decode('ascii')}")
print("\n=== Bob's signature (base64) ===")
print(f"\n{base64.b64encode(bob_signature).decode('ascii')}")

# Print Bob's RSA public key in hex for Alice to use
bob_rsa_pub_bytes = bob.signature.public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("\n=== Bob's RSA public key (base64) ===")
print(f"\n{base64.b64encode(bob_rsa_pub_bytes).decode('ascii')}")

# Receive Alice's DH serialized value, signature, and RSA public key
alice_serialized_b64 = input("\nPaste Alice's DH public value (base64): ")
alice_signature_b64 = input("\nPaste Alice's signature (base64): ")
alice_rsa_pub_b64 = input("\nPaste Alice's RSA public key (base64): ")

alice_serialized = base64.b64decode(alice_serialized_b64)
alice_signature = base64.b64decode(alice_signature_b64)
alice_rsa_pub_bytes = base64.b64decode(alice_rsa_pub_b64)

# Deserialize Alice's DH and RSA keys
alice_pub_key = bob.deserialize_public_value(alice_serialized)
alice_rsa_pub = serialization.load_der_public_key(alice_rsa_pub_bytes)

# Verify Alice's signature
verified = bob.verify_other_public(alice_serialized, alice_signature, alice_rsa_pub)
print(f"\nSignature verified? {verified}")

# Compute shared secret
shared_secret = bob.compute_shared_secret(alice_pub_key)
print(f"\nBob's shared secret: {shared_secret}")
