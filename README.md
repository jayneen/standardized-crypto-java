# asymmetric-crypto-java
## Description: 
A Java implementation of 128-bit symmetric encryption application using algorithms inspired by ECDHIES encryption, Schnorr signatures, SHA-3 hash, and SHAKE functions. 

## Contributors:
Kassie Whitney
Zane Swaims
Evgeniia Nemynova

## Instructions:
## How to Run:
1) Compile code with: javac Main.java
2) Run with: java Main
### Command Line Arguments:
The program accepts up to 3 command line arguments in the order: input file path, output file path, and a pass phrase. If the input file path or pass phrase are not provided they will be prompted for during runtime. If an output file path is not provided the application will default to "EncryptedFile.txt". The pass phrase must match between encryption and decryption modes.
### SHA-3/SHAKE Encryption:
Different security levels are offered for SHA-3 and SHAKE algorithms and are prompted for at runtime.