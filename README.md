# asymmetric-crypto-java
## Description: 
A Java implementation of 128-bit symmetric encryption application using algorithms inspired by ECDHIES encryption, Schnorr signatures, SHA-3 hash, and SHAKE functions.
Part 1: Povides an implementation of several SHA-3 and SHAKE inspired algorithms for hashing, tagging, encrypting, and decrypting.

## Contributors:
- Kassie Whitney
- Zane Swaims
- Evgeniia Nemynova

## Instructions:
### How to Run:
1) Compile code with: javac *.java
2) Run with: java Main
### Command Line Arguments:
The program accepts up to three command line arguments in the order: input file path, output file path, and a pass phrase. If the input file path or pass phrase are not provided they will be prompted for during runtime as needed. Otherwise, the provided arguments are reused for the entire runtime. If an output file path is not provided the application defaults to "EncryptedFile.txt" and will create new versions under that name. 
Additionally, the input file should not exceed ~2GB.
### Application Modes:
The application provides four basic functionalities that the user is prompted to select from at runtime (or q to quit):
1) Computes hashes of the provided file using SHA-3-256, -512, -224, and -384. Writes all hashes to the output file each on its own line.
2) Computes MAC tags of the provided file under the provided pass phrase using SHAKE-128 and -256. If no input file is provided the application prompts for a message. Additionally, the user will be prompted for the desired length of the tags in bits. Resulting tags are written to the output file each on its own line.
3) Encrypts a file with the pass phrase using SHAKE-128 and generates a MAC tag with SHA-3-256.
4) Decrypts a file generated with the algorithm in mode 3 and verifies its MAC tag.
The pass phrase must match between encryption and decryption modes.
