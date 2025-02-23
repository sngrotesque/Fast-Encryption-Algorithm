# Fast Encryption Algorithm (FEA)

This is FEA.

The block size of this encryption algorithm is 128 bits, and the key length is 256 bits (unchangeable). Currently, four encryption methods are provided (CBC, ECB, CTR, CFB).

This algorithm has good Avalanche effects.

The number of rounds for encryption (or decryption) is 4.

It can provide good performance even without hardware acceleration (encryption algorithms on the market, such as AES and ChaCha20, both have hardware acceleration).

Attempt to maintain the same level of security as AES, or even exceed AES, with fewer encryption rounds.

You can easily use this algorithm on both Windows and Linux systems, but as some code does not fully support Mac OS, if you are a Mac OS user, you will need to make slight modifications to the code (The modified code does not include the algorithm itself).

