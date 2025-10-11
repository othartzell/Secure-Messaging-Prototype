# Owen Hartzell 801188721 ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# Testing the functionality of the KDF class

# Imports
from DiffieHellman import DiffieHellman
from KDF import KDF

# Performing DHE to get a shared secret for testing
print("\n=== Performing DHE to get shared secret ===")
# Create Alice
alice = DiffieHellman()
p, g = alice.get_params()

# Create bob
bob = DiffieHellman(p=p, g=g)

# Computing shared secret for alice and bob
alice_shared_secret = alice.compute_shared_secret(bob.public_key)
bob_shared_secret = bob.compute_shared_secret(alice.public_key)

# Verify shared secrets match before testing
print("\nAlice's computed shared secret")
print(alice_shared_secret)
print("\nBob's computed shared secret")
print(bob_shared_secret)
print("\nChecking if secrets match")
print(alice_shared_secret == bob_shared_secret)

# Testing KDF
print("\n=== Testing KDF ===")
# Deriving Alice's key
alice_derived_key = KDF.derive_key(alice_shared_secret, iterations= 1000)

# Deriving Bob's key
bob_derived_key = KDF.derive_key(bob_shared_secret, iterations=1000)

# Checking if keys are the same, function should be deterministic
print("\nAlice's derived key")
print(alice_derived_key.hex())
print("\nBob's derived key")
print(bob_derived_key.hex())
print("\nChecking if keys match")
print(alice_derived_key == bob_derived_key)