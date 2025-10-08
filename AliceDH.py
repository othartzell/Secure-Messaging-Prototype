# Owen Hartzell 801188721 ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# Logic for user Alice to test DiffieHellman.py

from DiffieHellman import DiffieHellman
from cryptography.hazmat.primitives import serialization
import base64

# Create Alice
alice = DiffieHellman()
alice_pub = alice.get_public_value()
p, g = alice.get_params()

# Printing public values
print("\n=== Alice ===")
print(f"p: {p}")
print(f"g: {g}")
print(f"Alice's public value (g^a mod p): {alice_pub}")

# Sign and serialize DH public value
alice_serialized = alice.serialize_public_value()
alice_signature = alice.sign_public()

print("\n=== Alice's DH public value (base64) ===")
print(f"\n{base64.b64encode(alice_serialized).decode('ascii')}")
print("\n=== Alice's signature (base64) ===")
print(f"\n{base64.b64encode(alice_signature).decode('ascii')}")

# Print Alice's RSA public key in base 64 for Bob to use
alice_rsa_pub_bytes = alice.signature.public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("\n=== Alice's RSA public key (base64) ===")
print(f"\n{base64.b64encode(alice_rsa_pub_bytes).decode('ascii')}")

# Receive Bob's DH serialized value, signature, and RSA public key
bob_serialized_b64 = input("\nPaste Bob's DH public value (base64): ")
bob_signature_b64 = input("\nPaste Bob's signature (base64): ")
bob_rsa_pub_b64 = input("\nPaste Bob's RSA public key (base64): ")

bob_serialized = base64.b64decode(bob_serialized_b64)
bob_signature = base64.b64decode(bob_signature_b64)
bob_rsa_pub_bytes = base64.b64decode(bob_rsa_pub_b64)

# Deserialize Bob's DH and RSA keys
bob_pub_key = alice.deserialize_public_value(bob_serialized)
bob_rsa_pub = serialization.load_der_public_key(bob_rsa_pub_bytes)

# Verify Bob's signature
verified = alice.verify_other_public(bob_serialized, bob_signature, bob_rsa_pub)
print(f"\nSignature verified? {verified}")

# Compute shared secret
shared_secret = alice.compute_shared_secret(bob_pub_key)
print(f"\nAlice's shared secret: {shared_secret}")
