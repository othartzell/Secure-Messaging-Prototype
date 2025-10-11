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
print("\n=== Bob for Secure Message Exchange ===")
# Getting parameters for DHE
p_str = input("\nPaste Alice's public value p: ")
g_str = input("\nPaste Alice's public value g: ")
p = int(p_str.strip())
g = int(g_str.strip())

# Creating Bob
bob = DiffieHellman(p=p, g=g)

# Creating digital signature for Bob and printing it for Alice
bob_rsa_pub = bob.signature.public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print("\n-- Bob's RSA public key --")
print(bob_rsa_pub.hex())

# Getting Alice's RSA public key to verify signature
alice_rsa_pub_hex = input("\nPaste Alice's RSA public key: ")
alice_rsa_pub = bytes.fromhex(alice_rsa_pub_hex)
alice_rsa_pub = serialization.load_der_public_key(alice_rsa_pub)

# Signing Bob's DH public value and printing it for Alice
bob_dh_pub = bob.serialize_public_value()
bob_dh_sig = bob.sign_public()

print("\n-- Bob's DH public value --")
print(bob_dh_pub.hex())
print("\n-- Bob's signature --")
print(bob_dh_sig.hex())

# Getting Alice's DH public value and signature
alice_dh_pub_hex = input("\nPaste Alice's DH Public Value: ")
alice_dh_sig_hex = input("\nPaste Alice's signature: ")

alice_dh_pub = bytes.fromhex(alice_dh_pub_hex)
alice_dh_sig = bytes.fromhex(alice_dh_sig_hex)

# Verifying Alice's signature
verified = bob.verify_other_public(alice_dh_pub, alice_dh_sig, alice_rsa_pub)
if verified != 1:
    print("INVALID SIGNATURE")
    exit()

# Generating session key using KDF.py
alice_pub_key = bob.deserialize_public_value(alice_dh_pub)
bob_shared_secret = bob.compute_shared_secret(alice_pub_key)
session_key = KDF.derive_key(bob_shared_secret, 1000)
print(f"\nSession key made: ", {session_key.hex()})

# Getting and decrypting secure message
print("\n=== Bob gets the secure message ===")
secure_message_hex = input("\nPaste the message hex from alice: ")
secure_message = bytes.fromhex(secure_message_hex)

# Bob uses the session key to decrypt the message
bob_cipher = SecureMessageExchange(session_key)

print("\n-- Components of the message --")
iv = secure_message[:16]
print("IV: ", iv.hex())
recieved_mac = secure_message[-32:]
print("Recieved MAC: ", recieved_mac.hex())
ciphertext = secure_message[16:-32]
print("Ciphertext: ", ciphertext.hex())

# Bob computes the mac of the ciphertext to validate integrity
computed_mac = bob_cipher.compute_hmac(ciphertext)
print(f"\n-- Bob computes the HMAC on the ciphertext --")
print(f"Received MAC: {recieved_mac.hex()}")
print(f"Expected MAC: {computed_mac.hex()}")

# Compare macs
if not secrets.compare_digest(recieved_mac, computed_mac):
    print("INTEGRITY CHECK FAILED: INVALID MAC")
    exit()
print("Integrity check successful")

# Bob decrypts the message after integrity check
decrypted_plaintext = bob_cipher.decrypt(secure_message)
print(f"\n=== Bob decrypts the ciphertext ===")
print(f"Decrypted Plaintext: '{decrypted_plaintext.decode()}'")