# Owen Hartzell ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# Testing the functionality of the Digital Signature class

# Imports
from DigitalSignature import DigitalSignature
from cryptography.hazmat.primitives import serialization

# Creating two users for testing
alice = DigitalSignature()
bob = DigitalSignature()

# Printing Alice's Public Key
print("Alice's Public Key:")
print(alice.public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode())

# Printing Bob's Public Key
print("Bob's Public Key:")
print(bob.public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode())

# Creating two messages for testing
message_a = b"Hello Bob"
message_b = b"Hello Alice"

# Signing the message as Alice and returning the hex to verify the funciton works
signature_a = alice.sign_message(message_a)
print("Alice's Signature:", signature_a.hex())

signature_b = bob.sign_message(message_b)
print("\nBob's Signature:", signature_b.hex())

# Verifying the signature of Alice's message using Alice's public key and the message as Bob (Should return 1 if working)
print("\nVerify Alice -> Bob:", bob.verify_signature(message_a, signature_a, alice.public_key))

# Attempting to verify the signature of Alice's message using Bob's public key as Bob (Should return 0 if working)
print("Verify Bob -> Bob:", bob.verify_signature(message_a, signature_a, bob.public_key))

# Verifying the signature of Bob's message using Bob's public key and the message as Alice (Should return 1 if working)
print("Verify Bob -> Alice:", alice.verify_signature(message_b, signature_b, bob.public_key))

# Attempting to verify the signature of Bob's message using Alices's public key as Alice (Should return 0 if working)
print("Verify Alice -> Alice:", alice.verify_signature(message_b, signature_b, alice.public_key))