# Owen Hartzell 801188721 ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# Imports
import secrets
from cryptography.hazmat.primitives import serialization
from DigitalSignature import DigitalSignature
from DiffieHellman import DiffieHellman
from KDF import KDF
from PRNG import PRNG
from SecureMessageExchange import SecureMessageExchange

# Testing functionality of Secure Message Exchange and implementation of all previous tasks
print("\n=== Alice for Secure Message Exchange ===")

# Creating Alice and getting DH parameters
alice = DiffieHellman()
p, g = alice.get_params()
print("\n-- Alice's DH parameters --")
print("p: ", p)
print("g: ", g)

# Generating digital signature for Alice and printing it for Bob
alice_rsa_pub = alice.signature.public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print("\n-- Alice's RSA public key --")
print(alice_rsa_pub.hex())

# Getting Bob's RSA public key to verify signature
bob_rsa_pub_hex = input("\nPaste Bob's RSA public key: ")
bob_rsa_pub = bytes.fromhex(bob_rsa_pub_hex)
bob_rsa_pub = serialization.load_der_public_key(bob_rsa_pub)

# Signing Alice's DH public value and printing it for Bob
alice_dh_pub = alice.serialize_public_value()
alice_dh_sig = alice.sign_public()

print("\n-- Alice's DH public value --")
print(alice_dh_pub.hex())
print("\n-- Alice's signature --")
print(alice_dh_sig.hex())

# Getting Bob's DH public value and signature
bob_dh_pub_hex = input("\nPaste Bob's DH Public Value: ")
bob_dh_sig_hex = input("\nPaste Bob's signature: ")

bob_dh_pub = bytes.fromhex(bob_dh_pub_hex)
bob_dh_sig = bytes.fromhex(bob_dh_sig_hex)

# Verifying Bob's signature
verified = alice.verify_other_public(bob_dh_pub, bob_dh_sig, bob_rsa_pub)
if verified != 1:
    print("INVALID SIGNATURE")
    exit()

# Generating session key using KDF.py
bob_pub_key = alice.deserialize_public_value(bob_dh_pub)
alice_shared_secret = alice.compute_shared_secret(bob_pub_key)
session_key = KDF.derive_key(alice_shared_secret, 1000)
print(f"\nSession key made: ", {session_key.hex()})

# Encrypting and sending a secure message
print("\n=== Alice sends a message ===")

alice_cipher = SecureMessageExchange(session_key)
alice_prng = PRNG()
plaintext = b"Testing the functionality of all classes for secure message exchange!"
print(f"Original Plaintext: '{plaintext.decode()}")

# Encrypting the plaintext message
iv = alice_prng.generate(16)
ciphertext = alice_cipher.sym_enc(plaintext, iv)
mac = alice_cipher.compute_hmac(ciphertext)
secure_message = iv + ciphertext + mac

print("\n=== Showing values for secure message exchange ===")
print(f"-- Symmetric Encryption --")
print(f"Input (Plaintext): {plaintext.decode()}")
print(f"Input (IV): {iv.hex()}")
print(f"Output (Ciphertext): {ciphertext.hex()}")
print(f"\n-- HMAC Computation --")
print(f"Input (Ciphertext): {ciphertext.hex()}")
print(f"Output (MAC): {mac.hex()}")
print(f"\n-- Ciphertext for Bob --")
print(f"{secure_message.hex()}")