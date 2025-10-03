# Owen Hartzell 801188721 ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# Testing the functionality of the Digital Signature class

from DigitalSignature import DigitalSignature

# Creating two users for testing
alice = DigitalSignature()
bob = DigitalSignature()

# Creating two messages for testing
message = b"hello world"
message_two = b"world hello"

# Signing the message as Alice and returning the hex to verify the funciton works
signature = alice.sign_message(message)
print("Signature:", signature.hex())

# Verifying the signature using Alice's public key and the message (Should return 1 if working)
print("Verify Alice -> Bob:", bob.verify_signature(message, signature, alice.public_key))

# Attempting to verify the signature using Bob's public key (Should return 0 if working)
print("Verify Bob -> Bob:", bob.verify_signature(message, signature, bob.public_key))

# Attempting to verify the signature of an arbitrary message with Alice's public key (Should return 0 if working)
print("Verify Alice -> Bob:", bob.verify_signature(message_two, signature, alice.public_key))