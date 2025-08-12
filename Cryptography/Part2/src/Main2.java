
/**
 * Assignment 1
 * part: 2
 *
 * This is the main application using the ECIES to provide three utility
 * modes: key pair generation, encryption, and decryption.
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
                        1 - to generate a key pair
                        2 - to encrypt a file
                        3 - to decrypt a file
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
                        passphrase = validatePassphrase(input, passphrase);
                        result = keyPairMode(passphrase);
                        break;
                    case "2":
                        inputFile = new File(validateInputFile(input, userInput));
                        keyFile = new File(validateKeyFile(input, userKey));
                        result = encryptMode(inputFile, keyFile);
                        break;
                    case "3":
                        isDecrypt = true;
                        inputFile = new File(validateInputFile(input, userInput));
                        keyFile = new File(validateKeyFile(input, userKey));
                        result = decryptMode(inputFile, keyFile);
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
    public static byte[] encryptMode(File inFile, File keyFile) throws IOException {
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
    public static byte[] decryptMode(File inFile, File keyFile) {
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
