from DiffieHellman import DiffieHellman

with open("parameters.txt", "r") as f:
    lines = f.readlines()
    p = int(lines[0].strip())
    g = int(lines[1].strip())

bob = DiffieHellman(p, g)
bob_pub = bob.get_public_value()

print("\n=== Bob ===")
print(f"Public value p: {p}")
print(f"Public value g: {g}")
print(f"Bob's public value (g^b mod p): {bob_pub}")

# Paste Alice's public value here
alice_pub_input = int(input("Paste Alice's public value (integer): "))
alice_pub_key = bob.get_peer_key(alice_pub_input)

# Compute shared secret
shared_secret = bob.compute_shared_secret(alice_pub_key)
print(f"Bob's shared secret: {shared_secret}")
