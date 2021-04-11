# Differential Cryptanalysis Attack
C implementation of a differential cryptanalysis attack on a toy cipher. This program is based on a tutorial written by Howard M. Heys at the Memorial University of Newfoundland. 

## Cipher Structure
The SPN structure allows for 16 bit inputs and 16 bit outputs. A single 4x4 s-box structure is used throughout the cipher (four in each round). The cipher structure has 4 rounds, each consisting of key mixing, substitution through an s-box, and permutation.

## Attack
A differential cryptanalysis attack is performed on the cipher by the program. A differential attack is a known plaintext probabilistic attack which exploits high probabilities of certain plaintext differences resulting in certain differences in the input to the last round of the cipher. When a plaintext difference yields a known input to the last round with sufficiently high probability, last round subkeys can be tried in succession to walk backwards through the network to the final round. If the guessed key leads to the desired last round input more often than any other, this key is likely the true key for the last round of the cipher. In this way, pieces of the key may be recovered, compromising the security of the cipher.

## Referenced Tutorial
H. M. Heys, _A Tutorial on Linear and Differential Cryptanalysis_, Memorial University of Newfoundland
