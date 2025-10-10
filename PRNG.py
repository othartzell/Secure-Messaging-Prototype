# Owen Hartzell 801188721 ohartzel@chartlotte.edu
# ITIS 6200 Project 1: Secure Messaging Prototype

# REFERENCES
    # Random number generation - https://cryptography.io/en/latest/random-numbers/
    # Generate pseudo-random numbers - https://docs.python.org/3/library/random.html
    # Secrets - https://docs.python.org/3/library/secrets.html
    # Time - https://docs.python.org/3/library/time.html

# Imports
import os
import random
import time

# Task 4: Pseudo-Random Number Generator (PRNG)

# Class for PRNG
class PRNG:
    # Initalizing the PRNG
    def __init__(self, seed=None):
        self.instance = random.Random()
        # Generating a seed value
        if seed is None:
            seed = os.urandom(32) + time.time_ns().to_bytes(8, 'big')
        
        self.instance.seed(seed)

    # Seeding PRNG to initialize internal state
    def seed(self, seed_value):
        self.instance.seed(seed_value)
    
    # Reseeding PRNG to add more randomness
    def reseed(self, reseed=None):
        # Getting current internal state and converting to bytes
        current_state = self.instance.getstate()
        current_bytes = str(current_state).encode('utf-8')

        if reseed is None:
            reseed = os.urandom(32) + time.time_ns().to_bytes(8, 'big')

        # Combining the current state with new reseed for more randmoness
        reseed = reseed + current_bytes

        self.instance.seed(reseed)

    # Generating the next random number
    def generate(self, num_bytes=16):
        random_bits = self.instance.getrandbits(num_bytes * 8)

        return random_bits.to_bytes(num_bytes, byteorder='big')
