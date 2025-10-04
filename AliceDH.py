from DiffieHellman import DiffieHellman

# Create Alice's DH instance
alice = DiffieHellman()
alice_pub = alice.get_public_value()
p, g = alice.get_params()

print("\n=== Alice ===")
print(f"Public value p: {p}")
print(f"Public value g: {g}")
print(f"Alice's public value (g^a mod p): {alice_pub}")

# Paste Bob's public value here
bob_pub_input = int(input("Paste Bob's public value (integer): "))
bob_pub_key = alice.get_peer_key(bob_pub_input)

# Compute shared secret
shared_secret = alice.compute_shared_secret(bob_pub_key)
print(f"Alice's shared secret: {shared_secret}")
