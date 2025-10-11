Owen Hartzell 801188721 ohartzel@charlotte.edu
ITIS6200 Project 1: Secure Message Exchange

General:
    Most files rely on the Cryptography library which can be installed using pip/pip3/python/python3 install cryptography
    For files in the "Tests" or "Old" directory, use the "-m" flag in terminal to run. Eg. "python3 -m Tests.TestDS"

    This project implments secure message exchange between two parties. The tasks in this project explore the building blocks of secure messaging where authenticity, integrity, and confidentiality are all upheld. Each task implements a functionality of the overall secure message exchange, and are used in task 5 togeather to achieve a secure exchange. Below is an outline of all required tasks, the goal of the task, my python classes and functions to complete the task, and how to use the test files for each task. 

Task 1: Digital Signature
    This task was to build a digital signature mechanism for Diffie-Hellman Eschange to defend against man in the middle attacks. I implemented an object oriented wrapper class called DigitalSignature with functions for key generation, hashing, signing, and verifying a signature. I used the manuals for the Cryptography library implement these functions.

    class DigitalSignature:
        def __init__:  Generates a 2048 private and public key pair for each instance, such as Alice or Bob

        def hash_message: Uses the senders private key and a message to hash the message using SHA256.

        def sign_message: Uses the senders private key and the hashed message to sign the hash with padding.

        def verify_signature: Uses the message, signature, and senders public key to verify the signature against the hash of the message. Returns 1 for valid and 0 for invalid

    TestDS.py:
        Follows the requested tests from the instructions, shows the public keys generated for Alice and Bob. Shows the digital signature generated for Alice and Bob. Shows the verifications with correct and incorrect public keys.
    
    To run the test file for this task, run the command "python3 -m Tests.TestDS"

Task 2: Diffie-Hellman Exchange
    This task was to develop a function or functions that implments the steps involved in Diffie-Hellman key exchange. The DiffieHellman class includes functions for generating public and private Diffie-Hellman parameters, signing the public value g^a or b mod p, verifying the signature on a recieved public value, and computing the shared secret. This class also takes advantage of the DigitalSignature class from task 1 for doing digital signatures. I again utilized the Cryptography library and its manuals to complete this task. Cryptography has built in tools for generating DH public and private values as seen below. 

    class DiffieHellman:
        def __init__: Initalizes a user with Diffie-Hellman private and public parameters. Generates new parameters for each communication. If parameters p and g already exist, the other user gets them from the sender. Generates a digital signature for signing the public g^a or b mod p.

        def get_params: Returns p and g to for printing to console for the other user, and for testing that p and g were generated. 

        def get_public_value: Returns the DH public value g^a or b mod p.

        def serialize_public_value: Converts the DH public value g^a or b mod p to a byte string. This is stored as a python object by the cryptography library so it needs to be converted for doing the digital signature.

        def deserialize_public_value: Converts the byte string for g^a or b mod p back to a python object.

        def sign_public: Signs the serialized public DH value g^a or b mod p.

        def verify_other_public: Uses the senders public RSA key, signature, DH public value, and recievers private key to verify the digital signature.

        def compute_shared_secret: Calculates g^ab mod p to return the shared secret. 

        def get_peer_key: Returns the senders public DH value g^a or b mod p as a python object. 

    AliceDH.py and BobDH.py: Test files for the DiffieHellman class. Shows the public parameters p and g generated. Shows the public DH values g^a mod p and g^b mod p generated. Verifies signatures on both ends. Computes the shared secrets on both ends.

    To run the test file for this task, run the command "python3 -m Tests.AliceDH" and "python3 -m Tests.BobDH" in separate terminals. When prompted, paste the values requested for the flow of the Diffie-Hellman exchange.

Task 3: Key Deriviation Function
    This task was to create a key derivation function (KDF) to generate a strong encryption key. This key is to be used in Diffie-Hellman exchange for feeding the shared secret into. For this task, the KDF needed to take 2 inputs, the shared secret from Diffie-Hellman and the number of times to run hashing. I used Cryptography's manuals to implement my KDF.

        def derive_key: Static method that takes in the shared secret and an int for iterations (the number of times to run hashing). Converts the shared secret to a byte string for hashing and stores the current hash as a temporary value. Runs a for loop to hash the shared secret for i (iterations) times. Returns the current hash
    
    TestKDF.py: Test file for the KDF class. Shows the shared secret computed by Alice and Bob and checks if they match before KDF. Shows the derived key after KDF and checks if they match. 

    To run the test file for this task, run the command "python3 -m Tests.TestKDF"

Task 4: Pseudo-Random Number Generator (PRNG)
    This task was to create a function for Pseudo-Random Number Generation. PRNGs from this function are to be used as IV and/or nonce in symmetric encryption. The PRNG class has the functions for init, seed, reseed, and generate a PRN. For this class, I used pythons built in random module, but this is NOT cryptographically secure. Using the Secrets module provides cryptographically secure numbers, but does not allow seeding. For a real world implementation of this class, random should NOT be used. Additionally, I used the maual pages for random, secrets, time, and random number generation to build this class.

    def __init__: Creates a private instance of random.Random(), pythons built in number generator. Generates a seed for the generator using os.urandom(). os.urandom() uses the operating systems built cryptographically secure PRNG to select bits based on different factors around the operating system. This can select data from sources like mice, network activity, etc. Then, more randomness is added by concatenating the current time in nanoseconds in bytes to the os.urandom output. Lastly, the generator is seeded. 

    def seed: Seeds the random number generator with the seed. 

    def reseed: Reseeds the random number generator with more entrophy. Gets the current state which is stored as a touple. Converts the touple to bytes for adding randomness. Generates a new random byte string using the same method as before, 32 random bytes from the os concatenated with the current time in nanoseconds in bytes. Then concatenates the current state with the new random bits before seeding the number generator with more entrophy. 

    def generate: Generates the next random number by calling getrandbits() on itself. This is a built in function of the python random number generator, this number is generated based on the seed. These bits are then converted to a byte string to be used as an IV. Returns the PRN

    TestPRNG.py: Test file for the PRNG class. The test file includes tests for showing randomness by printing a sequence of outputs from the generate fuction, showing determinism by using the same seed value for two outputsof the generate function, and the effects of seeding/reseeding the PRNG. 

To run the test file for this task, run the command "python3 -m Tests.TestPrng"

Task 5: Secure Message Exchange
    This task was to bring all of the previous tasks togeather and implement a secure message exchange using a symmetric encryption algorithm. I chose to use AES CBC mode to acomplish this. Additionally, it is implemented as encrypt then mac for verifying integrity before attempting to decrypt. The secure message exchange class includes functions for init, symmetric encryption, symmetric decryption, computing hmac, encrypt, and decrypt. I used Cryptography's modules for encryption, padding, and CBC mode to implement my secure message exchange. 

    class SecureMessageExchange:
        def __init__: Initalizes an object with a session key derived using the KDF class from task 3.

        def sym_enc: Performs cipher block chaining symmetric encryption with the plaintext and iv in bytes using Cryptography's CBC module. Includes padding per Cryptography's manual page to ensure the correct block size. Assembles ciphertext from encrypted blocks. Returns the ciphertext. 

        def sym_dec: Performs cbc decryption with the ciphertext and iv in bytes using Cryptography's built in CBC module. Unpadds the decrypted text and returns plaintext. 

        def compute_hmac: Uses Cryptography's built in hmac module to compute the hmac of the ciphertext. 

        def encrypt: Creates the final ciphertext to send by generating an iv using the prng class, encrypts the plaintext using the iv and plaintext for the sym_enc function, computes the hmac using the compute_hmac function, and concatenates all 3 values to return. 

        def decrypt: Decrypts the given ciphertext by first splitting the recieved ciphertext into iv, mac, and ciphertext. Then the hmac is computed using the compute_hmac function with the recieved ciphertext and performs an integrity check by comparing the computed and recieved hmacs. If the hmacs dont match, raises an error and fails to decrypt. If the hmacs do match, decrypts the ciphertext using the sym_dec function and returns the plaintext. 
    
    AliceSME.py and BobSME.py: Test files for the SecureMessageExchange class. Like the earlier test files for Diffie-Hellman, copy and paste the values between terminals to show the full flow of the secure exchange. These files show the public values for Diffie-Hellman, the RSA public keys for both users, the Diffie-Hellman public values for each user, the digital signature for each user. 
    
    For Alice, the tests show Alice's plaintext message input, the iv input, the resulting ciphertext, the hmac being computed based on the ciphertext generated, and the ciphertext to send to Bob. 

    For Bob, the tests show the inputted ciphertext message as hex from alice, the break down of the ciphertext to show iv, mac, and ciphertext, Bob computing the expected mac for the ciphertext, a check against the recieved mac, and finally the decrypted plaintext.

    To run these test files, run the commands "python3 AliceSME.py" and "python3 BobSME.py" in separate terminals and copy and paste the values requested at each step.

Task 6: Tampering Experiment (Optional Task)
    This task was a continuance of task 5 where a malicious actor, Mallory, is able to modify the message during transport. On the recievers end (Bob), they should be able to detect that this has happened and fail to decrypt the message. The SecureMessageExchange class already has this implemented in the check for the MAC value. The test files from task 5 can be used again, but the message can be modified before pasting to Bob's terminal to show this function working. Bob will detect that the message has been tampered with by the MAC value not matching and will not attempt to decrypt.

    
