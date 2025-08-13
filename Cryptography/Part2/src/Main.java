/**
 * Assignment 1
 * part: 2
 * 
 * This is the main application using SHA3, SHAKE, ECIES, and Schnorr inspired algorithms
 * to provide seven utility modes: hash computation, tag generation, symmetric file 
 * encryption and decryption, key pair generation, and asymmetric encryption and decryption.
 * It accepts optional command line arguments in the order: input file path, output 
 * file path, and pass phrase. Do not use input files greater than ~2GB.
 * 
 * @author Kassie Whitney, Zane Swaims, Evgeniia Nemynova
 * @version 9.8.25
 */

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.StandardOpenOption;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class Main {
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
                        Q - to quit the program

                        """);

                userMode = input.nextLine().replace("\"", "");
                if (userMode.equalsIgnoreCase("q")) {
                    input.close();
                    break;
                }

                // Apply mode
                File inputFile = null;
                File keyFile = null;
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
                        result = asymmetricEncryptMode(inputFile, keyFile);
                        break;
                    case "7":
                        isDecrypt = true;
                        inputFile = new File(validateInputFile(input, userInput));
                        keyFile = new File(validateKeyFile(input, userKey));
                        result = asymmetricDecryptMode(inputFile, keyFile);
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

                } else if (isDecrypt) {
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
                ;
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
            Files.writeString(theFile.toPath(), formattedHex + "\n", StandardOpenOption.APPEND);
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
        while (passphrase == null) {
            System.out.println("Please enter a passphrase: ");
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
        while (inputFile == null || inputFile.equals("")) {
            System.out.println("Please enter an input file path: ");
            inputFile = input.nextLine();
        }
        if (!Files.exists(new File(inputFile).toPath())) {
            throw new IOException();
        }

        System.out.print("Input file size: ");
        fileSize(inputFile.getBytes(StandardCharsets.UTF_8));

        return inputFile;
    }

    /**
     * Prompts the user for an public key file if null and print its size.
     *
     * @param input     scanner
     * @param inputFile current input file path
     */
    public static String validateKeyFile(Scanner input, String keyFile) throws IOException {
        while (keyFile == null || keyFile.equals("")) {
            System.out.println("Please enter a public key file path: ");
            keyFile = input.nextLine();
        }
        if (!Files.exists(new File(keyFile).toPath())) {
            throw new IOException();
        }

        System.out.print("Key file size: ");
        fileSize(keyFile.getBytes(StandardCharsets.UTF_8));

        return keyFile;
    }    

    /***************************************************************************/
    /*******************************  MODES  ***********************************/
    /***************************************************************************/


    /*******************************  PART 1  **********************************/
    /**
     * Handles the first task of hashing a user specified file
     * using SHA-3-256 and -512 (bonus: -224, 384).
     *
     * @param inFile user specified input file
     * @return all computed hashes
     */
    public static byte[] hashMode(File inFile) {

        // prompt for security level and verify with a cursed while loop
        int ShaSecLevel = 0;
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
            switch (ShaSecLevel) {
                case 224:
                    sha = SHA3SHAKE.SHA3(224, Files.readAllBytes(inFile.toPath()),
                            null);
                    break;
                case 256:
                    sha = SHA3SHAKE.SHA3(256, Files.readAllBytes(inFile.toPath()),
                            null);
                    break;
                case 384:
                    sha = SHA3SHAKE.SHA3(384, Files.readAllBytes(inFile.toPath()),
                            null);
                    break;
                case 512:
                    sha = SHA3SHAKE.SHA3(512, Files.readAllBytes(inFile.toPath()),
                            null);
                    break;
            }

            System.out.println("Outputting...");

        } catch (final IOException ioe) {
            System.out.println("Unable to convert the file into a binary.");
        }

        return sha;
    }

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
        byte[] key = SHA3SHAKE.SHAKE(128, passPhrase.getBytes(StandardCharsets.UTF_8), 16, null);

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

        byte[] plaintext = new byte[0];
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
        byte[] key = SHA3SHAKE.SHAKE(128, passPhrase.getBytes(StandardCharsets.UTF_8), 16, null);

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

    /*******************************  PART 2  **********************************/

    /**
     * Handles the first task of generating an elliptic key pair
     * from a given passphrase.
     *
     * @param passphrase user specified pass phrase
     * @return generated elliptic key pair
     */
    public static byte[] keyPairMode(String passphrase) {
        // might need to change to byte[][]?
        return null;
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
    public static byte[] asymmetricEncryptMode(File inFile, File keyFile) throws IOException {
        return null;
    }

    /**
     * Combines the decryption and Schnorr verification tasks under
     * a provided public key.
     *
     * @param inFile  user specified input file
     * @param keyFile user specified public key containing file
     * @return decrypted message
     */
    public static byte[] asymmetricDecryptMode(File inFile, File keyFile) {
        return null;
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

}
