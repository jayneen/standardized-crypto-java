# asymmetric-crypto-java
## Description: 
A Java implementation of 128-bit symmetric and asymmetric encryption applications. 
#### Part 1: 
Povides an implementation of several SHA-3 and SHAKE inspired symmetric algorithms for hashing, tagging, encrypting, and decrypting. 
#### Part 2: 
Provides an implementation of ECIES and Schnorr inspired asymmetric algorithms for signing, verifying, encrypting, and decrypting.

## Contributors:
- Kassie Whitney
- Zane Swaims
- Evgeniia Nemynova

## Instructions:
### How to Run:
1) Compile code with: javac *.java
2) Run with: java Main2

### Command Line Arguments:
#### Part 1:
The program accepts up to three command line arguments in the order: input file path, output file path, and a pass phrase. 
#### Part 2:
The program accepts up to four command line arguments in the order: input file path, output file path, pass phrase, key pair file. 

If the input file path, pass phrase, or key pair file are not provided via the command line arguments they will be prompted for during runtime as needed. Otherwise, the provided arguments are reused for the entire runtime. If an output file path is not provided the application defaults to "EncryptedFile.txt" for encryption or other related actions and "DecryptedFile.txt" for decryption and will create new versions under that name. If it is provided, the output is appended to the provided output file.
The input file should not exceed ~2GB.

### Application Modes:
#### Part 1:
The application provides four basic functionalities that the user is prompted to select from at runtime (or q to quit):
1) Computes hashes of the provided file using SHA-3-256, -512, -224, or -384. This mode prompts the user for the desired security level and appends the hash to the output file.
2) Computes MAC tags of the provided file under the provided pass phrase using SHAKE-128 or -256. If no input file is provided the application prompts for a message. Additionally, the user will be prompted for the desired security level and tag length in bits. Resulting tag is appended to the output file.
3) Encrypts a file with the pass phrase using SHAKE-128 and generates a MAC tag with SHA-3-256. The user is prompted for a pass phrase and input file if none are provided.
4) Decrypts a file generated with the algorithm in mode 3 and verifies its MAC tag. The user is prompted for a pass phrase and input file if none are provided.
The pass phrase must match between encryption and decryption modes.
#### Part 2:
The application provides three basic functionalities that the user is prompted to select from at runtime (or q to quit):
1) Computes the ECIES key pair based on the provided pass phrase and writes it to output file. If no pass phrase is provided the user is prompted for one at run time.
2) Encrypts a file under the user provided key pair with a Schnorr signature and writes the encrypted data to the output file.
3) Decrypts a file generated with the algorithm in mode 2 with the provided key pair and verifies its signature.

## Known bugs and Notes:
Error messages due to invalid inputs are generic for all underlying exceptions.
