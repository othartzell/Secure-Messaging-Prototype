# Owen Hartzell 801188721 ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# Testing the functionality of the Diffie Hellman class in a single terminal

# Imports
from Old.DiffieHellmanOld import DiffieHellman
from cryptography.hazmat.primitives import serialization
import base64

# Create Alice and Bob with same DH parameters so p and g are shared
alice = DiffieHellman()
bob = DiffieHellman(parameters=alice.parameters)

# Printing p and g
print("\n=== Public Values ===")
p = alice.parameters.parameter_numbers().p
g = alice.parameters.parameter_numbers().g
print(f"p: {p}\ng: {g}")

# Printing the DH public values as integers (g^a mod p and g^b mod p)
alice_g_a = alice.public_key.public_numbers().y
bob_g_b   = bob.public_key.public_numbers().y

print("\n=== Alice’s g^a mod p ===")
print(f"{alice_g_a}")
print("\n=== Bob’s g^b mod p ===")
print(f"{bob_g_b}")

# Signing the DH public value
sign_a = alice.sign_public()
sign_b = bob.sign_public()

# Verifying the signature on the DH public value and printing the result 1 or 0
alice_verifies = alice.verify_other_public(bob.serialize_public_value(), sign_b, bob.signature.public_key)
bob_verifies   = bob.verify_other_public(alice.serialize_public_value(), sign_a, alice.signature.public_key)

print("\n=== Alice’s Signature ===")
print(f"{base64.b64encode(sign_a).decode('ascii')}")
print("\n=== Bob’s Signature ===")
print(f"{base64.b64encode(sign_b).decode('ascii')}")

# Computing the shared secret and comparing to see if they match
alice_shared = alice.shared_secret(bob.public_key)
bob_shared = bob.shared_secret(alice.public_key)
print("\n=== Alice’s computed shared secret ===")
print(f"{int.from_bytes(alice_shared)}")
print("\n=== Bob’s computed shared secret ")
print(f"{int.from_bytes(bob_shared)}")
print("\n=== Checking if secrets match ===")
print(alice_shared == bob_shared)