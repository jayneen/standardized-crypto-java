
/*
  Assignment 1
  part: 2
  <p>
  This is the main application using SHA3, SHAKE, ECIES, and Schnorr inspired algorithms
  to provide seven utility modes: hash computation, tag generation, symmetric file
  encryption and decryption, key pair generation, and asymmetric encryption and decryption.
  It accepts optional command line arguments in the order: input file path, output
  file path, and pass phrase. Do not use input files greater than ~2GB.

  @author Kassie Whitney, Zane Swaims, Evgeniia Nemynova
 * @version 9.8.25
 */

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.StandardOpenOption;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class Main2 {
    private static final Scanner input = new Scanner(System.in);
    private static boolean isDecrypt = false;

    public static void main(String[] args) {

        while (true) {
            isDecrypt = false;

            String userInput = null; // file to read from
            String userOutput = null; // file to write to (creates or overwrites)
            String passphrase = null;
            String userKey = null; // file containing public key

            if (args.length > 0)
                userInput = args[0];
            if (args.length > 1)
                userOutput = args[1];
            if (args.length > 2)
                passphrase = args[2];
            if (args.length > 3)
                userKey = args[2];

            try {
                // Select program mode or quit
                String userMode;
                System.out.print("""
                        Select an application mode:

                        Symmetric encryption:
                        1 - to compute hashes
                        2 - to compute tags
                        3 - to encrypt a file
                        4 - to decrypt a file

                        Asymmetric encryption:
                        5 - to generate a key pair
                        6 - to encrypt a file
                        7 - to decrypt a file

                        Asymmetric signatures:
                        8 - to sign a file
                        9 - to verify a signature
                        Q - to quit the program

                        """);

                userMode = input.nextLine().replace("\"", "");
                if (userMode.equalsIgnoreCase("q")) {
                    input.close();
                    break;
                }

                // Apply mode
                File inputFile = null;
                File keyFile;
                byte[] result;
                switch (userMode) {
                    case "1":
                        inputFile = new File(validateInputFile(input, userInput));
                        result = hashMode(inputFile);
                        break;
                    case "2":
                        if (args.length > 0)
                            inputFile = new File(validateInputFile(input, userInput));
                        passphrase = validatePassphrase(input, passphrase);
                        result = tagMode(inputFile, passphrase);
                        break;
                    case "3":
                        inputFile = new File(validateInputFile(input, userInput));
                        passphrase = validatePassphrase(input, passphrase);
                        result = symmetricEncryptMode(inputFile, passphrase);
                        break;
                    case "4":
                        isDecrypt = true;
                        inputFile = new File(validateInputFile(input, userInput));
                        passphrase = validatePassphrase(input, passphrase);
                        result = symmetricDecryptMode(inputFile, passphrase);
                        break;
                    case "5":
                        passphrase = validatePassphrase(input, passphrase);
                        result = keyPairMode(passphrase);
                        break;
                    case "6":
                        inputFile = new File(validateInputFile(input, userInput));
                        keyFile = new File(validateKeyFile(input, userKey));
                        // TODO:updated signirute here
                        passphrase = validatePassphrase(input, passphrase);
                        result = asymmetricEncryptMode(inputFile, keyFile, passphrase);
                        break;
                    case "7":
                        isDecrypt = true;
                        inputFile = new File(validateInputFile(input, userInput));
                        keyFile = new File(validateKeyFile(input, userKey));
                        passphrase = validatePassphrase(input, passphrase);
                        result = asymmetricDecryptMode(inputFile, keyFile, passphrase);
                        break;
                    case "8":
                        inputFile = new File(validateInputFile(input, userInput));
                        passphrase = validatePassphrase(input, passphrase);
                        result = signMode(inputFile, passphrase);
                        break;
                    case "9":
                        isDecrypt = true;
                        inputFile = new File(validateInputFile(input, userInput));
                        File sigFile = new File(validateSignatureFile(input, null));
                        keyFile = new File(validateKeyFile(input, userKey));
                        result = verifyMode(inputFile, sigFile, keyFile);
                        break;
                    default:
                        System.out.println("Invalid mode entered. Please select a valid mode.\n");
                        continue; // restart the while loop
                }

                // Print post-processing size
                System.out.print("Post processing: ");
                fileSize(result);

                // Write output
                final File finalDocument;
                if (userOutput == null && !isDecrypt) {
                    // Creating a new default file recursively
                    finalDocument = checkFile(new File("EncryptedFile.txt"));

                } else if (userOutput == null && isDecrypt) {
                    finalDocument = checkFile(new File("DecryptedFile.txt"));

                } else {
                    // Create or overwrite specified file

                    finalDocument = new File(userOutput);
                }
                if (isDecrypt) {
                    String plaintext = new String(result, StandardCharsets.UTF_8);
                    Files.writeString(finalDocument.toPath(), plaintext);
                    System.out.println("Decrypted plaintext written to: " + finalDocument.getName() + "\n");
                } else {
                    convertToHexAndWrite(finalDocument, result);
                }
                System.out.println("Wrote to " + finalDocument.getName() + "\n");

            } catch (NumberFormatException | InvalidParameterException | InvalidPathException
                    | IOException invalidPathException) {
                System.out.println("""
                        Invalid file path, contents, or pass phrase.
                        Please try again!
                        """);
                // avoid softlock due to bad command line input
                if (args.length > 0) {
                    System.out.println("""
                            Ending due to invalid command line file paths.
                            """);
                    return;
                }
            }
        }

    }

    /**
     * Prints the size of the file or passphrase for informational purposes.
     *
     * @param array the file or passphrase in byte[]
     */
    private static void fileSize(byte[] array) {
        if (array.length < 1024) {
            System.out.println("Total Bytes read: " + (double) array.length);
        } else if (1025 <= array.length && array.length < 1_048_576) {
            System.out.println("Total KiB read: " + (double) array.length / 1025);
        } else if (1_048_576 <= array.length) {
            System.out.println("Total MiB read: " + (double) array.length / 1_048_576);
        }
    }

    /**
     * Recursively checks if the file already exists and creates a new file.
     *
     * @param theFile the file that will store the encrypted document
     * @return the newly generated file to be writen on.
     */
    public static File checkFile(File theFile) {
        try {
            if (!theFile.createNewFile()) {
                return checkFile(theFile, 1);
            }
        } catch (final IOException ioException) {
            System.out.println("Unable to create new file!");
        }
        return theFile;
    }

    /**
     * Recursively checks if the file already exists and creates a new file.
     *
     * @param theFile the file that will store the encrypted document
     * @param counter the counter to copy new files with similar names
     * @return the newly generated file to be writen on.
     */
    private static File checkFile(File theFile, int counter) {
        try {
            if (isDecrypt) {
                if (!theFile.createNewFile()) {
                    theFile = new File("DecryptedFile-" + counter + ".txt");
                    counter++;
                    return checkFile(theFile, counter);
                }
            } else {
                if (!theFile.createNewFile()) {
                    theFile = new File("EncryptedFile-" + counter + ".txt");
                    counter++;
                    return checkFile(theFile, counter);
                }
            }
        } catch (IOException ioException) {
            System.out.println("Unable to create new file!");
        }
        return theFile;
    }

    public static void convertToHexAndWrite(final File theFile,
            final byte[] theEncryptedFile) {
        final StringBuilder sb = new StringBuilder(theEncryptedFile.length * 2);

        for (byte theFileByte : theEncryptedFile) {
            sb.append(String.format("%02x", theFileByte));
        }

        String rawHex = sb.toString();

        // Format with a space every 8 characters
        StringBuilder formattedHex = new StringBuilder();
        for (int i = 0; i < rawHex.length(); i++) {
            formattedHex.append(rawHex.charAt(i));
            if ((i + 1) % 8 == 0 && i + 1 < rawHex.length()) {
                formattedHex.append(' ');
            }
        }

        try {
            Files.writeString(theFile.toPath(), formattedHex, StandardOpenOption.CREATE);
        } catch (final IOException ioe) {
            System.out.println("Invalid File Path!");
        }
    }

    /**
     * Prompts the user for a pass phrase if null and print its size.
     *
     * @param input      scanner
     * @param passphrase current passphrase
     */
    public static String validatePassphrase(Scanner input, String passphrase) {
        while (passphrase == null || passphrase.trim().isEmpty()) {
            System.out.print("Please enter a passphrase: ");
            passphrase = input.nextLine();
        }
        System.out.print("Pass phrase size: ");
        fileSize(passphrase.getBytes(StandardCharsets.UTF_8));
        return passphrase;
    }

    /**
     * Prompts the user for an input file if null and print its size.
     *
     * @param input     scanner
     * @param inputFile current input file path
     */
    public static String validateInputFile(Scanner input, String inputFile) throws IOException {
        while (inputFile == null || inputFile.isEmpty()) {
            System.out.println("Please enter an input file path: ");
            inputFile = input.nextLine();
        }
        if (!Files.exists(new File(inputFile).toPath())) {
            throw new IOException();
        }

        System.out.print("Input file size: ");
        fileSize(Files.readAllBytes(new File(inputFile).toPath()));

        return inputFile;
    }

    /**
     * Prompts the user for an public key file if null and print its size.
     *
     * @param input   scanner
     * @param keyFile current input file path
     */
    public static String validateKeyFile(Scanner input, String keyFile) throws IOException {
        while (keyFile == null || keyFile.isEmpty()) {
            System.out.println("Please enter a public key file path: ");
            keyFile = input.nextLine();
        }

        if (!Files.exists(new File(keyFile).toPath())) {
            throw new IOException();
        }

        System.out.print("Key file size: ");
        fileSize(Files.readAllBytes(new File(keyFile).toPath()));

        return keyFile;
    }

    public static String validateSignatureFile(Scanner input, String sigFile) throws IOException {
        while (sigFile == null || sigFile.isEmpty()) {
            System.out.println("Please enter a signature file path: ");
            sigFile = input.nextLine();
        }
        if (!Files.exists(new File(sigFile).toPath())) {
            throw new IOException();
        }
        System.out.print("Signature file size: ");
        fileSize(Files.readAllBytes(new File(sigFile).toPath()));
        return sigFile;
    }

    // ***************************************************************************/
    // ******************************* MODES ***********************************/
    // ***************************************************************************/

    // ******************************* PART 1 **********************************/
    /**
     * Handles the first task of hashing a user specified file
     * using SHA-3-256 and -512 (bonus: -224, 384).
     *
     * @param inFile user specified input file
     * @return all computed hashes
     */
    public static byte[] hashMode(File inFile) {

        // prompt for security level and verify with a cursed while loop
        int ShaSecLevel;
        while (true) {
            System.out.print("Please enter a security level for SHA-3 (224, 256, 384, 512) > ");
            ShaSecLevel = Integer.parseInt(input.nextLine());
            if (!(ShaSecLevel == 224 || ShaSecLevel == 256 || ShaSecLevel == 384 || ShaSecLevel == 512)) {
                System.out.println("Invalid security level entered.");
            } else {
                break;
            }
        }

        System.out.println("Computing a SHA-3-" + ShaSecLevel + " hash...");

        byte[] sha = new byte[0];
        try {
            sha = switch (ShaSecLevel) {
                case 224 -> SHA3SHAKE.SHA3(224, Files.readAllBytes(inFile.toPath()),
                        null);
                case 256 -> SHA3SHAKE.SHA3(256, Files.readAllBytes(inFile.toPath()),
                        null);
                case 384 -> SHA3SHAKE.SHA3(384, Files.readAllBytes(inFile.toPath()),
                        null);
                case 512 -> SHA3SHAKE.SHA3(512, Files.readAllBytes(inFile.toPath()),
                        null);
                default -> sha;
            };

            System.out.println("Outputting...");

        } catch (final IOException ioe) {
            System.out.println("Unable to convert the file into a binary.");
        }

        return sha;
    }

    // TODO init and absorb sha3shake as per specs
    /**
     * Handles the second task of creating MAC tags of user specified length
     * for a user specified file and under a user specified pass phrase
     * using SHAKE-128 and -256 (bonus: compute tags for direct text input).
     *
     * @param inFile     user specified input file.
     *                   Pass NULL to have the user use a text
     *                   input.
     * @param passPhrase user specified pass phrase
     * @return all computed tags
     */
    public static byte[] tagMode(File inFile, String passPhrase) {

        // prompt for security level and verify
        int ShakeSecLevel = 0;
        while (true) {
            System.out.print("Please enter a security level for SHAKE (128,256) > ");
            ShakeSecLevel = Integer.parseInt(input.nextLine());
            if (!(ShakeSecLevel == 128 || ShakeSecLevel == 256)) {
                System.out.println("Invalid security level entered.");
            } else {
                break;
            }
        }

        byte[] shake = new byte[0];
        byte[] kMac = new byte[0];
        int len = 0;

        if (inFile == null) {

            System.out.print("\n\nPlease enter a message: > ");
            String message = input.nextLine();

            System.out.print("\n\nPlease designate the length of your MAC tag in bits > ");

            len = Integer.parseInt(String.valueOf(input.nextLine()));

            byte[] msgByte = message.getBytes(StandardCharsets.UTF_8);
            byte[] thePass = passPhrase.getBytes(StandardCharsets.UTF_8);
            // kMac = new byte[thePass.length + msgByte.length];

            // System.arraycopy(thePass, 0, kMac, 0, thePass.length);
            // System.arraycopy(msgByte, 0, kMac, thePass.length, msgByte.length);
            byte[] tTag = "T".getBytes(StandardCharsets.UTF_8);
            kMac = new byte[thePass.length + msgByte.length + tTag.length];
            System.arraycopy(thePass, 0, kMac, 0, thePass.length);
            System.arraycopy(msgByte, 0, kMac, thePass.length, msgByte.length);
            System.arraycopy(tTag, 0, kMac, thePass.length + msgByte.length, tTag.length);

        } else {

            try {

                System.out.print("\n\nPlease designate the length of your MAC tag in bits > ");

                len = Integer.parseInt(String.valueOf(input.nextLine()));

                byte[] theFile = Files.readAllBytes(inFile.toPath());
                byte[] thePass = passPhrase.getBytes(StandardCharsets.UTF_8);
                // kMac = new byte[theFile.length + thePass.length];

                // System.arraycopy(thePass, 0, kMac, 0, thePass.length);
                // System.arraycopy(theFile, 0, kMac, thePass.length, theFile.length);
                byte[] tTag = "T".getBytes(StandardCharsets.UTF_8);
                kMac = new byte[thePass.length + theFile.length + tTag.length];
                System.arraycopy(thePass, 0, kMac, 0, thePass.length);
                System.arraycopy(theFile, 0, kMac, thePass.length, theFile.length);
                System.arraycopy(tTag, 0, kMac, thePass.length + theFile.length, tTag.length);

            } catch (final IOException exception) {

                System.out.println("\nUnable to convert the file into a binary.");

            } catch (final NumberFormatException nfe) {

                System.out.println("\nThe length provided is invalid. Please try again.\n\n");
                tagMode(inFile, passPhrase);

            }
        }

        if (kMac.length == 0 || len == 0) {
            throw new InvalidParameterException("The length must be greater than 0!");
        }

        System.out.println("Computing a SHAKE-" + ShakeSecLevel + " tag...");
        switch (ShakeSecLevel) {
            case 128:
                shake = SHA3SHAKE.SHAKE(128, kMac, len, null);
                break;
            case 256:
                shake = SHA3SHAKE.SHAKE(256, kMac, len, null);
                break;
        }

        System.out.println("Outputting...");

        return shake;
    }

    /**
     * Handles the third task of ecnrypting a user specified file under
     * the user specified pass phrase by:
     * 1) hashing the pass phrase with SHAKE-128 as the key
     * 2) obtaining a random 128-bit nonce
     * 3) hashing the nonce and the data file using SHAKE-128 as a stream cipher
     * (bonus: include a MAC tag using SHA-3-256 and the same key)
     *
     * @param inFile     user specified input file
     * @param passPhrase user specified pass phrase
     * @return the cryptogram (nonce || cyphertext || MAC)
     */
    public static byte[] symmetricEncryptMode(File inFile, String passPhrase) throws IOException {
        // I am throwing an exception because of this, I chose this as the way to handle
        // it
        // instead of making a new method and being complicated. The upside is this is
        // easy,
        // the downside is I load the entire file into memory at once and thus cant
        // handle
        // more than the JVMs memory. If there is an OUT_OF_MEMORY error, it is from
        // this.
        byte[] fileBytes = Files.readAllBytes(inFile.toPath());

        // 1) hashing the pass phrase with SHAKE-128 as the key
        byte[] key = SHA3SHAKE.SHAKE(128, passPhrase.getBytes(StandardCharsets.UTF_8), 128,
                null);

        // 2) obtaining a random 128-bit nonce
        byte[] nonce = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(nonce);

        // 3) hashing the nonce and the key using SHAKE-128 as a stream cipher (nonce +
        // key)
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(128);
        shake.absorb(nonce);
        shake.absorb(key);

        byte[] keystream = shake.squeeze(fileBytes.length);

        System.out.println(Arrays.toString(keystream));
        // Encrypting, ciphertext = plaintext XOR (step 3)
        byte[] ciphertext = new byte[fileBytes.length];
        for (int i = 0; i < fileBytes.length; i++) {
            ciphertext[i] = (byte) (fileBytes[i] ^ keystream[i]);
        }

        // (bonus: include a MAC tag using SHA-3-256 and the same key) (key +
        // ciphertext)
        byte[] macInput = new byte[key.length + ciphertext.length];
        System.arraycopy(key, 0, macInput, 0, key.length);
        System.arraycopy(ciphertext, 0, macInput, key.length, ciphertext.length);
        byte[] mac = SHA3SHAKE.SHA3(256, macInput, null);

        // Putting it together, nonce + ciphertext + mac
        byte[] output = new byte[nonce.length + ciphertext.length + mac.length];
        System.arraycopy(nonce, 0, output, 0, nonce.length);
        System.arraycopy(ciphertext, 0, output, nonce.length, ciphertext.length);
        System.arraycopy(mac, 0, output, nonce.length + ciphertext.length, mac.length);

        return output;
    }

    /**
     * Handles the fourth task of decrypting a user specified file under
     * the user specified pass phrase using SHAKE-128 and the supplied nonce.
     * (bonus: verify the MAC tag if included)
     *
     * @param inFile     user specified input file
     * @param passPhrase user specified pass phrase
     * @return decrypted message
     */
    public static byte[] symmetricDecryptMode(File inFile, String passPhrase) {

        // Read hex string from file (with spaces)

        byte[] plaintext;
        String hexString;
        try {
            hexString = Files.readString(inFile.toPath());
        } catch (IOException e) {
            throw new RuntimeException("Failed to read input file for decryption", e);
        }

        // Remove all whitespace from hex string
        hexString = hexString.replaceAll("\\s+", "");

        // Convert hex string to byte array
        byte[] encryptedData = hexStringToByteArray(hexString);

        final int NONCE_LENGTH = 16;
        final int MAC_LENGTH = 32;

        if (encryptedData.length < NONCE_LENGTH + MAC_LENGTH) {
            throw new IllegalArgumentException("Input data too short");
        }

        byte[] nonce = Arrays.copyOfRange(encryptedData, 0, NONCE_LENGTH);
        byte[] mac = Arrays.copyOfRange(encryptedData, encryptedData.length - MAC_LENGTH, encryptedData.length);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, NONCE_LENGTH, encryptedData.length - MAC_LENGTH);

        // Derive key from passPhrase (SHAKE-128, 128 bits)
        byte[] key = SHA3SHAKE.SHAKE(128, passPhrase.getBytes(StandardCharsets.UTF_8), 128,
                null);

        // Verify MAC = SHA3-256(key || ciphertext)
        byte[] macInput = new byte[key.length + ciphertext.length];
        System.arraycopy(key, 0, macInput, 0, key.length);
        System.arraycopy(ciphertext, 0, macInput, key.length, ciphertext.length);
        byte[] macComputed = SHA3SHAKE.SHA3(256, macInput, null);

        if (!Arrays.equals(mac, macComputed)) {
            throw new InvalidParameterException("***!Incorrect password!***");
        } else {

            // Generate keystream the same way as encryption (SHAKE-128 absorbs nonce then
            // key)
            SHA3SHAKE shake = new SHA3SHAKE();
            shake.init(128);
            shake.absorb(nonce);
            shake.absorb(key);
            byte[] keystream = shake.squeeze(ciphertext.length);

            // XOR ciphertext with keystream to get plaintext
            plaintext = new byte[ciphertext.length];
            for (int i = 0; i < ciphertext.length; i++) {
                plaintext[i] = (byte) (ciphertext[i] ^ keystream[i]);
            }
        }

        return plaintext;
    }

    // *********************** PART 2 ********************************
    /**
     * Handles the first task of generating an elliptic key pair
     * from a given passphrase.
     *
     * @param passphrase user specified pass phrase
     * @return generated elliptic key pair
     */
    public static byte[] keyPairMode(String passphrase) {
        Edwards ed = new Edwards();
        // byte[] absorbedPass = SHA3SHAKE.SHAKE(128,
        // passphrase.getBytes(StandardCharsets.UTF_8), 32 * 8, null);
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(128);
        shake.absorb(passphrase.getBytes(StandardCharsets.UTF_8));
        byte[] absorbedPass = shake.squeeze(32);

        BigInteger s = new BigInteger(1, absorbedPass);
        s = s.mod(ed.getR());
        Edwards.Point V = ed.gen().mul(s);
        if (V.getX().testBit(0)) {
            s = ed.getR().subtract(s);
            V = V.negate();
        }

        System.out.println("Gen: " + ed.gen());
        System.out.println("r * G: " + ed.gen().mul(ed.getR()));
        System.out.println("s * G: " + ed.gen()
                .mul(new BigInteger("16665465170803196137237183189757970819661769527195913594111126976751630942579")));

        System.out.println(BigInteger.ONE.shiftLeft(254).subtract(new BigInteger(
                "87175310462106073678594642380840586067")));

        System.out.println("r: " + ed.getR());
        System.out.println("s: " + s);
        System.out.println("V: " + V);
        System.out.println("P: " + ed.P);
        byte[] yBytes = toFixedLengthBytes(V.y, 32);
        byte[] out = new byte[33];
        System.arraycopy(yBytes, 0, out, 0, 32);
        out[32] = (byte) (V.getX().testBit(0) ? 1 : 0);
        return out;
    }

    /**
     * Combines the encryption and Schnorr signing tasks by using ECIES under a
     * given
     * public key file.
     *
     * @param inFile  user specified input file
     * @param keyFile user specified public key containing file
     * @return the cryptogram
     */
    @SuppressWarnings("unused")
    public static byte[] asymmetricEncryptMode(File inFile, File keyFile, String passphrase) throws IOException {
        Edwards E = new Edwards();
        // String keyHex = new String(Files.readAllBytes(keyFile.toPath())).replaceAll("
        // ", "");
        // byte[] keyBytes = hexStringToByteArray(keyHex);
        // if (keyBytes.length != 33) {
        // throw new IllegalArgumentException("Key file must be exactly 33 bytes (y ||
        // xLSB).");
        // }
        // byte[] yBytes = Arrays.copyOfRange(keyBytes, 0, 32);
        // boolean xLsb = keyBytes[32] != 0;
        // BigInteger yV = new BigInteger(1, yBytes);
        // Edwards.Point V = E.getPoint(yV, xLsb);
        // if (V.isZero()) {
        // throw new InvalidParameterException("Invalid public key.");
        // }
        Edwards.Point V = E.gen()
                .mul(new BigInteger("16665465170803196137237183189757970819661769527195913594111126976751630942579"));

        byte[] m = Files.readAllBytes(inFile.toPath());
        int rbytes = (E.getR().bitLength() + 7) >> 3;
        byte[] seed = new SecureRandom().generateSeed(rbytes << 1);
        // BigInteger k = new BigInteger(1, seed).mod(E.getR());
        BigInteger k = BigInteger.TWO;

        Edwards.Point G = E.gen();
        Edwards.Point W = V.mul(k);
        Edwards.Point Z = G.mul(k);
        // byte[] yW = toFixedLength(W.y, 32);
        // byte[] kk = SHA3SHAKE.SHAKE(256, yW, 64 * 8, null);
        // byte[] k_a = Arrays.copyOfRange(kk, 0, 32);
        // byte[] k_e = Arrays.copyOfRange(kk, 32, 64);
        // byte[] keystream = SHA3SHAKE.SHAKE(128, k_e, m.length * 8, null);
        // byte[] c = new byte[m.length];
        // for (int i = 0; i < m.length; i++)
        // c[i] = (byte) (m[i] ^ keystream[i]);
        // byte[] macInput = new byte[k_a.length + c.length];
        // System.arraycopy(k_a, 0, macInput, 0, k_a.length);
        // System.arraycopy(c, 0, macInput, k_a.length, c.length);

        // byte[] t = SHA3SHAKE.SHA3(256, macInput, null);
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(256);
        shake.absorb(W.y.toByteArray());
        byte[] ka = shake.squeeze(32);
        byte[] ke = shake.squeeze(32);

        shake.init(128);
        shake.absorb(ke);
        byte[] mask = shake.squeeze(m.length);
        byte[] c = new byte[m.length];

        for (int i = 0; i < m.length; i++)
            c[i] = (byte) (m[i] ^ mask[i]);

        // shake.init(256);
        // shake.absorb(ka);
        // shake.absorb(c);
        // byte[] t = shake.digest();

        // Assuming 'ka' and 'c' are your byte arrays to be hashed.

        // Step 1: Combine 'ka' and 'c' into a single byte array
        byte[] combinedMessage = new byte[ka.length + c.length];
        System.arraycopy(ka, 0, combinedMessage, 0, ka.length);
        System.arraycopy(c, 0, combinedMessage, ka.length, c.length);

        // Step 2: Call the static SHA3 method
        // The '256' is the desired output length in bits for SHA3-256.
        // 'combinedMessage' is the data to be hashed.
        // 'null' for the output buffer means the method will allocate a new one.
        byte[] t = SHA3SHAKE.SHA3(256, combinedMessage, null);

        System.out.println("W: " + W);
        System.out.println("Z: " + Z);
        System.out.println("ka: " + Arrays.toString(ka));
        System.out.println("ke: " + Arrays.toString(ke));
        System.out.println("c: " + Arrays.toString(c));
        System.out.println("t: " + Arrays.toString(t));

        byte[] yZ = toFixedLength(Z.y, 32);
        byte xlsbZ = (byte) (Z.getX().testBit(0) ? 1 : 0);
        ByteBuffer bb = ByteBuffer.allocate(32 + 1 + 4 + c.length + 32).order(ByteOrder.BIG_ENDIAN);
        bb.put(yZ);
        bb.put(xlsbZ);
        bb.putInt(c.length);
        bb.put(c);
        bb.put(t);
        return bb.array();
    }

    // Helper to convert BigInteger to fixed-length byte array (big-endian),
    // left-padded with zeros
    @SuppressWarnings("SameParameterValue")
    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        if (raw.length == length) {
            return raw;
        } else if (raw.length > length) {
            // BigInteger byte array can have leading zero for sign, so trim if needed
            int start = raw.length - length;
            byte[] trimmed = new byte[length];
            System.arraycopy(raw, start, trimmed, 0, length);
            return trimmed;
        } else {
            // pad with leading zeros
            byte[] padded = new byte[length];
            System.arraycopy(raw, 0, padded, length - raw.length, raw.length);
            return padded;
        }
    }

    /**
     * Combines the decryption and Schnorr verification tasks under
     * a provided public key.
     *
     * @param inFile     user specified input file
     * @param keyFile    user specified public key containing file
     * @param passphrase user specified pass phrase used to generate the key file
     * @return decrypted message
     */
    @SuppressWarnings("unused")
    public static byte[] asymmetricDecryptMode(File inFile, File keyFile, String passphrase) {
        // TODO un-hardcode this
        Edwards ed = new Edwards();
        BigInteger zx = new BigInteger("9437071788689923860285188864243445848829034305114716688925961299686472351778");
        BigInteger zy = new BigInteger("33335288469882025483739701342541534780286781789447071287975993879306170570424");
        Edwards.Point Z = new Edwards.Point(zx, zy);
        byte[] c = { 94, 117, 3 };
        byte[] t = { -101, 9, -55, 20, 47, 20, -12, 92, -2, 0, 70, 123, -106, -99, -22, 120, -74, 95, -28, -37, -50,
                -121, -53, 109, -122, 69, 45, 23, 126, 40, 67, -25 };
        BigInteger S = new BigInteger("16665465170803196137237183189757970819661769527195913594111126976751630942579");

        Edwards.Point W = Z.mul(S);
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(256);
        shake.absorb(W.y.toByteArray());
        byte[] ka = shake.squeeze(32);
        byte[] ke = shake.squeeze(32);

        byte[] combinedMessage = new byte[ka.length + c.length];
        System.arraycopy(ka, 0, combinedMessage, 0, ka.length);
        System.arraycopy(c, 0, combinedMessage, ka.length, c.length);
        byte[] tp = SHA3SHAKE.SHA3(256, combinedMessage, null);

        shake.init(128);
        shake.absorb(ke);
        byte[] temp = shake.squeeze(c.length);

        byte[] m = new byte[c.length];
        for (int i = 0; i < c.length; i++)
            m[i] = (byte) (c[i] ^ temp[i]);

        // TODO prints out in decimal and errors on file writing
        System.out.println(Arrays.toString(m));

        if(tp != t){
            throw new InvalidParameterException("Decryption Error.");
        }

        return m;

        // // 1) Get the passphrase (since case "7" didn't capture it)
        // // String passphrase = validatePassphrase(input, null);

        // // 2) Read the cryptogram file as hex (bytes → hex with spaces)
        // final String hex;
        // try {
        // hex = Files.readString(inFile.toPath()).replaceAll("\\s+", "");
        // } catch (IOException e) {
        // throw new RuntimeException("Failed to read input file", e);
        // }
        // final byte[] blob = hexStringToByteArray(hex);

        // // Expected wire format (clean, self-delimiting):
        // // 32B y(Z) big-endian, unsigned
        // // 1B xLSB(Z) (0x00 or 0x01)
        // // 4B cLen (big-endian)
        // // cLen bytes c
        // // 32B t = SHA3-256(k_a || c)
        // if (blob.length < 32 + 1 + 4 + 32) {
        // throw new InvalidParameterException("Cipher blob too short.");
        // }
        // int idx = 0;
        // byte[] yZbytes = Arrays.copyOfRange(blob, idx, idx + 32);
        // idx += 32;
        // boolean xLsbZ = blob[idx++] != 0;
        // int cLen = ByteBuffer.wrap(blob, idx,
        // 4).order(ByteOrder.BIG_ENDIAN).getInt();
        // idx += 4;
        // if (cLen < 0 || blob.length != 32 + 1 + 4 + cLen + 32) {
        // throw new InvalidParameterException("Malformed ciphertext length.");
        // }
        // byte[] c = Arrays.copyOfRange(blob, idx, idx + cLen);
        // idx += cLen;
        // byte[] t = Arrays.copyOfRange(blob, idx, idx + 32);

        // // 3) Derive private key s from passphrase (SHAKE-128 → 32B → mod r) and
        // enforce
        // // xLSB(V)==0
        // Edwards E = new Edwards();
        // BigInteger r = E.getR();

        // byte[] sBytesRaw = SHA3SHAKE.SHAKE(128,
        // passphrase.getBytes(StandardCharsets.UTF_8), 256, null);
        // BigInteger s = new BigInteger(1, sBytesRaw).mod(r);

        // Edwards.Point G = E.gen();
        // Edwards.Point V = G.mul(s);
        // if (V.getX().testBit(0)) { // if LSB(x(V)) == 1
        // s = r.subtract(s); // s ← r − s
        // // noinspection UnusedAssignment
        // V = V.negate(); // (optional here; we only need s fixed)
        // }

        // // 4) Reconstruct Z and compute W = s · Z
        // BigInteger yZ = new BigInteger(1, yZbytes);
        // Edwards.Point Z = E.getPoint(yZ, xLsbZ);
        // if (Z.isZero())
        // throw new InvalidParameterException("Invalid Z in cryptogram.");
        // Edwards.Point W = Z.mul(s);

        // // 5) k_a || k_e = SHAKE-256( y(W) ), 64 bytes total
        // byte[] yW = toFixedLength(W.y, 32); // package-private y is accessible from
        // default package
        // byte[] kk = SHA3SHAKE.SHAKE(256, yW, 64 * 8, null);
        // byte[] k_a = Arrays.copyOfRange(kk, 0, 32);
        // byte[] k_e = Arrays.copyOfRange(kk, 32, 64);

        // // 6) Verify tag: t' = SHA3-256( k_a || c )
        // byte[] macInput = new byte[k_a.length + c.length];
        // System.arraycopy(k_a, 0, macInput, 0, k_a.length);
        // System.arraycopy(c, 0, macInput, k_a.length, c.length);
        // byte[] tPrime = SHA3SHAKE.SHA3(256, macInput, null);
        // if (!constantTimeEquals(tPrime, t)) {
        // throw new InvalidParameterException("*** Authentication failed (bad tag)
        // ***");
        // }

        // // 7) Decrypt: m = c XOR SHAKE-128(k_e, |c|)
        // byte[] keystream = SHA3SHAKE.SHAKE(128, k_e, c.length * 8, null);
        // byte[] m = new byte[c.length];
        // for (int i = 0; i < c.length; i++)
        // m[i] = (byte) (c[i] ^ keystream[i]);

        // return m;
    }

    public static byte[] signMode(File inFile, String passphrase) throws IOException {
        byte[] message = Files.readAllBytes(inFile.toPath());
        Edwards curve = new Edwards();
        Schnorr schnorr = new Schnorr();
        Schnorr.Signature sig = schnorr.generateKeypair(message, curve, passphrase);
        byte[] zBytes = toFixedLength(sig.z, 32);
        byte[] hBytes = toFixedLength(sig.h, 32);
        byte[] out = new byte[64];
        System.arraycopy(zBytes, 0, out, 0, 32);
        System.arraycopy(hBytes, 0, out, 32, 32);
        return out;
    }

    public static byte[] verifyMode(File inFile, File sigFile, File keyFile) throws IOException {
        byte[] message = Files.readAllBytes(inFile.toPath());
        String sigHex = new String(Files.readAllBytes(sigFile.toPath())).replaceAll(" ", "");
        byte[] sig = hexStringToByteArray(sigHex);
        if (sig.length != 64) {
            throw new IllegalArgumentException("Signature file must be exactly 64 bytes.");
        }
        byte[] zB = Arrays.copyOfRange(sig, 0, 32);
        byte[] hB = Arrays.copyOfRange(sig, 32, 64);
        BigInteger z = new BigInteger(1, zB);
        BigInteger h = new BigInteger(1, hB);
        String keyHex = new String(Files.readAllBytes(keyFile.toPath())).replaceAll(" ", "");
        byte[] keyBytes = hexStringToByteArray(keyHex);
        if (keyBytes.length != 33) {
            throw new IllegalArgumentException("Key file must be exactly 33 bytes (y || xLSB).");
        }
        byte[] yBytes = Arrays.copyOfRange(keyBytes, 0, 32);
        boolean xLsb = keyBytes[32] != 0;
        Edwards E = new Edwards();
        Edwards.Point V = E.getPoint(new BigInteger(1, yBytes), xLsb);
        if (V.isZero()) {
            throw new InvalidParameterException("Invalid public key.");
        }
        Schnorr schnorr = new Schnorr();
        boolean ok = schnorr.verify(message, E, V, z, h);
        return ok ? "VALID".getBytes(StandardCharsets.UTF_8) : "INVALID".getBytes(StandardCharsets.UTF_8);
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length)
            return false;
        int v = 0;
        for (int i = 0; i < a.length; i++)
            v |= (a[i] ^ b[i]);
        return v == 0;
    }

    // Helper to convert hex string to byte array
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // Helper to convert BigInteger to fixed 32-byte array
    @SuppressWarnings("SameParameterValue")
    private static byte[] toFixedLengthBytes(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] fixed = new byte[length];

        if (raw.length > length) {
            // Truncate leading zero byte if present
            System.arraycopy(raw, raw.length - length, fixed, 0, length);
        } else {
            System.arraycopy(raw, 0, fixed, length - raw.length, raw.length);
        }

        return fixed;
    }

}
