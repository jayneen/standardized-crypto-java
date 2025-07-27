# asymmetric-crypto-java
## Description: 
A Java implementation of 128-bit symmetric encryption application using algorithms inspired by ECDHIES encryption, Schnorr signatures, SHA-3 hash, and SHAKE functions. 

## Contributors:
- Kassie Whitney
- Zane Swaims
- Evgeniia Nemynova

## Instructions:
### How to Run:
1) Compile code with: javac Main.java
2) Run with: java Main
### Command Line Arguments:
The program accepts up to 3 command line arguments in the order: input file path, output file path, and a pass phrase. If the input file path or pass phrase are not provided they will be prompted for during runtime. If an output file path is not provided the application defaults to "EncryptedFile.txt" and will create new versions under that name. 
### Application Modes:
The application provides four basic functionalities and is prompted to select one at run time:
- 1 - Computes hashes of the provided file using SHA-3-256, -512, -224, and -384. Writes all hashes to the output file each on its own line.
- 2 - Computes MAC tags.
- 3 - Encrypts a file.
- 4 - Decrypts a file.
The pass phrase must match between encryption and decryption modes.
### SHA-3/SHAKE Encryption:
Different security levels are offered for SHA-3 and SHAKE algorithms and are prompted for at runtime.
