# asymmetric-crypto-java
## Description: 
A Java implementation of 128-bit symmetric and asymmetric encryption applications. Part 1 provides symmetric cryptographic features based on an implementation of several SHA-3 and SHAKE inspired algorithms for hashing, tagging, encrypting, and decrypting. Part 2 provides additional asymmetric features including custom implementations of ECIES and Schnorr inspired algorithms for signing, verifying, encrypting, and decrypting.

## Contributors:
- Kassie Whitney
- Zane Swaims
- Evgeniia Nemynova

## Instructions:
### How to Run:
1) Navigate to the folder containing the desired source code
2) Compile with: javac *.java
3) Run with: java Main

### Command Line Arguments:
The program accepts up to five command line arguments in the order: input file path, output file path, pass phrase, key pair file, and signature file.
If the input file path, pass phrase, key pair file, or signature file are not provided via the command line arguments they will be prompted for during runtime as needed. Otherwise, the provided arguments are reused for the entire runtime. If an output file path is not provided the application defaults to "EncryptedFile.txt" for encryption or other related actions and "DecryptedFile.txt" for decryption and will create new versions under that name. If it is provided, the output clears and overwrites the current contents of the output file.
The input file should not exceed ~2GB.

### Application Modes:
The application provides nine basic functionalities that the user is prompted to select from at runtime (or q to quit):
#### Symmetric:
1) Computes hashes of the provided file using SHA-3-256, -512, -224, or -384. This mode prompts the user for the desired security level and writes the hash to the output file.
2) Computes MAC tags of the provided file under the provided pass phrase using SHAKE-128 or -256. If no input file is provided the application prompts for a message. Additionally, the user will be prompted for the desired security level and tag length in bytes. Resulting tag is written to the output file.
3) Encrypts a file with the pass phrase using SHAKE-128 and generates a MAC tag with SHA-3-256. The user is prompted for a pass phrase and input file if none are provided.
4) Decrypts a file generated with the algorithm in mode 3 and verifies its MAC tag. The user is prompted for a pass phrase and input file if none are provided.
The pass phrase must match between encryption and decryption modes.
#### Asymmetric:
6) Computes the ECIES key pair based on the provided pass phrase and writes the public key to the output file.
7) Encrypts a file under the user provided public key via file and writes the encrypted data to the output file.
8) Decrypts a file generated with the algorithm in mode 6 with the provided key and writes the message to the output file.
9) Signs an input file with a Schnorr signature using a password-derived private key and writes it to output file.
10) Verifies a Schnorr signature for the given data file under the given public key file.
The passphrase and key pair must match between all asymmetric operations.

## Known bugs and Notes:
- Desired security levels cannot be specified via command line and are prompted for during runtime.
- Encrypted ciphertext adheres to the following format: nonce || ciphertext || MAC.
- Invalid security level is handled via recursion, and thus if it is incorrectly entered too many times may crash the VM or cause sluggish run speeds.
- SHA3SHAKE init() differentiates between SHA-3 and SHAKE inits internally by passing negative suffixes for SHAKE and positive for SHA-3.
- Both SHAKE and SHA-3 algorithms pass all test vectors except Monte Carlo, where they fail on the first step.
- Part 2 key generation: While the live demo used 512-bit byte array squeezed from passphrase via SHAKE-128, the output obtained this way does not match the specifications. Instead, the current version squeezes a 256-bit byte array as instructed in the specs, which generates valid and secure points on the curve. This approach is used in keyPairMode(), generateKeypair(), and asymmetricDecryptMode().
