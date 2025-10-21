# Owen Hartzell ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# Testing the functionality of the PRNG class

from PRNG import PRNG

# Test 1, showing randomness by printing multiple PRNs
print("\n=== Showing randomness with a sequence of outputs ===")
prng = PRNG()
for i in range(10):
    random_bytes = prng.generate()
    print(f"PRNG {i+1}: {random_bytes.hex()}")

# Test 2, showing determinism by seeding two PRNs with the same seed
print("\n=== Showing determinism with same seed ===")
# Seeding both PRNs with the same seed
same_seed = 12345
prng1 = PRNG(seed=same_seed)
prng2 = PRNG(seed=same_seed)

# Generating PRN and printing results
random_bytes1 = prng1.generate().hex()
random_bytes2 = prng2.generate().hex()
print("Seed: ", same_seed)
print("PRN 1: ", random_bytes1)
print("PRN 2: ", random_bytes2)
print(random_bytes1 == random_bytes2)

# Test 3, showing the impact of seeding/reseeding
print("\n=== Showing the impact of seeding/reseeding ===")
# Generating 2 PRNs with the same seed and printing the result
prng3 = PRNG(seed=12345)
prng4 = PRNG(seed=54321)

print(f"PRN 3: {prng3.generate().hex()}")
print(f"PRN 4: {prng4.generate().hex()}")
print(prng3.generate().hex() == prng4.generate().hex())

# Reseeding both PRNs and printing the results
prng3.reseed()
prng4.reseed()

print(f"\nPRN 3 Reseeded: {prng3.generate().hex()}")
print(f"PRN 4 Reseeded: {prng4.generate().hex()}")
print(prng3.generate().hex() == prng4.generate().hex())