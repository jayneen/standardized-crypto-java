import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidParameterException;
import java.util.Arrays;
import java.util.Scanner;

public class Main {
    private static final Scanner input = new Scanner(System.in);

    public static void main(String[] args) {

        while (true) {

            String userInput = null; // file to read from
            String userOutput = null; // file to write to (creates or overwrites)
            String passphrase = null;

            if (args.length > 0)
                userInput = args[0];
            if (args.length > 1)
                userOutput = args[1];
            if (args.length > 2)
                passphrase = args[2];

            try {
                // Select program mode or quit
                String userMode = null;
                System.out.print("""
                        Select an application mode:
                        1 - to compute hashes
                        2 - to compute tags
                        3 - to encrypt a file
                        4 - to decrypt a file
                        Q - to quit the program
                        """);
                userMode = input.nextLine().replace("\"", "");
                if (userMode.equalsIgnoreCase("q")) {
                    input.close();
                    break;
                }

                // Apply mode and validate required inputs
                File inputFile = null;
                byte[][] result;
                switch (userMode) {
                    case "1":
                        inputFile = new File(validateInputFile(input, userInput));
                        result = hashMode(inputFile);
                        break;
                    case "2":

                        inputFile = new File(validateInputFile(input, userInput));
                        passphrase = validatePassphrase(input, passphrase);
                        result = tagMode(inputFile, passphrase);
                        break;
                    case "3":
                        inputFile = new File(validateInputFile(input, userInput));
                        passphrase = validatePassphrase(input, passphrase);
                        result = new byte[1][];
                        result[0] = encryptMode(inputFile, passphrase);
                        break;
                    case "4":
                        inputFile = new File(validateInputFile(input, userInput));
                        passphrase = validatePassphrase(input, passphrase);
                        result = new byte[1][];
                        result[0] = decryptMode(inputFile, passphrase);
                        break;
                    default:
                        System.out.println("Invalid mode entered. Please select a valid mode.\n");
                        continue; // restart the while loop
                }


                // Print post processing size
                System.out.println("Post processing: ");
                for (int i = 0; i < result.length; i++) {
                    System.out.println("Output " + (i + 1) + ": ");
                    assert result[i] != null;
                    fileSize(result[i]);
                }

                // Write output
                final File finalDocument;
                if (userOutput == null) {
                    // Creating a new default file recursively
                    finalDocument = checkFile(new File("EncryptedFile.txt"));
                    // Files.writeString(finalDocument.toPath(), output + "\n",
                    // StandardOpenOption.APPEND);
                } else {
                    // Create or overwrite specified file
                    finalDocument = new File(userOutput);
                    // Files.writeString(finalDocument.toPath(), output, StandardOpenOption.CREATE);
                }
                for (byte[] bytes : result) {
                    convertToHexAndWrite(finalDocument, bytes);
                }
                System.out.println("Wrote to " + finalDocument.getName() + "\n");

            } catch (InvalidPathException | IOException invalidPathException) {
                System.out.println("""
                        This is an invalid file path or the file is unable to convert to binary!
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
            if (!theFile.createNewFile()) {
                theFile = new File("EncryptedFile-" + counter + ".txt");
                counter++;
                return checkFile(theFile, counter);
            }
        } catch (IOException ioException) {
            System.out.println("Unable to create new file!");
        }
        return theFile;
    }

    /**
     * XOR's the hashed passphrase and the hashed document to encrypt the document.
     *
     * @param theHashedPassPhrase the user chosen passphrase *Hash length must equal
     *                            to the
     *                            document hash length!
     * @param theHashedDocument   the hashed users document from the provided path.
     * @return the users encrypted hashed document.
     */
    private static byte[] encryptFile(final byte[] theHashedPassPhrase,
                                      final byte[] theHashedDocument) {

        if (theHashedDocument.length != theHashedPassPhrase.length) {
            throw new InvalidParameterException("The hash for the passphrase and the hash " +
                    "for the document must be the same size!");
        }

        final byte[] encryptedMessage = new byte[theHashedDocument.length];

        for (int i = 0; i < theHashedDocument.length; i++) {

            encryptedMessage[i] = (byte) (theHashedPassPhrase[i] ^ theHashedDocument[i]);
        }

        return encryptedMessage;
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
            Files.writeString(theFile.toPath(), formattedHex.toString() + "\n", StandardOpenOption.APPEND);
        } catch (final IOException ioe) {
            System.out.println("Invalid File Path!");
        }
    }

    /**
     * Prompts the user for a pass phrase if null and prints its size.
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
     * Prompts the user for an input file if null and prints its size.
     *
     * @param input     scanner
     * @param inputFile current input file path
     */
    public static String validateInputFile(Scanner input, String inputFile) throws IOException {
        while (inputFile == null) {
            System.out.println("Please enter an input file path: ");
            inputFile = input.nextLine();
        }

        System.out.print("Input file size: ");
        fileSize(Files.readAllBytes(Paths.get(inputFile)));

        return inputFile;
    }

    /**
     * Handles the first task of hashing a user specified file
     * using SHA-3-256 and -512 (bonus: -224, 384).
     *
     * @param inFile user specified input file
     * @return all computed hashes
     */
    public static byte[][] hashMode(File inFile) {

        // call all 4 hashes or prompt for just 1 at a time

        System.out.println("Computing the SHA-3-256, SHA-3-512, SHA-3-224, and SHA-3-384...");

        StringBuilder result = new StringBuilder();
        byte[] sha256 = new byte[0];
        byte[] sha224 = new byte[0];
        byte[] sha384 = new byte[0];
        byte[] sha512 = new byte[0];

        try {

            sha256 = SHA3SHAKE.SHA3(256, Files.readAllBytes(inFile.toPath()),
                    null);
            sha512 = SHA3SHAKE.SHA3(512, Files.readAllBytes(inFile.toPath()),
                    null);
            System.out.println("Outputting...");
            sha224 = SHA3SHAKE.SHA3(224, Files.readAllBytes(inFile.toPath()),
                    null);
            sha384 = SHA3SHAKE.SHA3(384, Files.readAllBytes(inFile.toPath()),
                    null);

            result.append("SHA-3-256: ").append(Arrays.toString(sha256));
            result.append("\n\nSHA-3-512: ").append(Arrays.toString(sha512));
            result.append("\n\nSHA-3-224: ").append(Arrays.toString(sha224));
            result.append("\n\nSHA-3-384: ").append(Arrays.toString(sha384));

            System.out.println(result);

        } catch (final IOException ioe) {
            System.out.println("Unable to convert the file into a binary.");
        }

        return new byte[][]{sha256, sha224, sha384, sha512};
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
    public static byte[][] tagMode(File inFile, String passPhrase) {
        StringBuilder result = new StringBuilder();
        byte[] shake128;
        byte[] shake256;
        byte[] kMac = new byte[0];
        int len = 0;


        try {

            System.out.print("\n\nPlease designate the length of your MACs tag > ");

            len = Integer.parseInt(String.valueOf(input.nextLine()));

            byte[] theFile = Files.readAllBytes(inFile.toPath());
            byte[] thePass = passPhrase.getBytes(StandardCharsets.UTF_8);
            kMac = new byte[theFile.length + thePass.length];

            System.arraycopy(thePass, 0, kMac, 0, thePass.length);
            System.arraycopy(theFile, 0, kMac, thePass.length, theFile.length);

        } catch (final IOException exception) {

            System.out.println("\nUnable to convert the file into a binary.");

        } catch (final NumberFormatException nfe) {

            System.out.println("\nThe length provided is invalid. Please try again.\n\n");
            tagMode(inFile, passPhrase);

        }


        if (kMac.length == 0 || len == 0) {
            throw new InvalidParameterException("The length must be greater than 0!");
        }

        System.out.println("Computing the SHAKE-128 and SHAKE-256");

        shake128 = SHA3SHAKE.SHAKE(128, kMac, len, null);

        System.out.println("Outputting...");

        shake256 = SHA3SHAKE.SHAKE(256, kMac, len, null);

        result.append("SHAKE-128: ").append(Arrays.toString(shake128));
        result.append("\n\nSHAKE-256: ").append(Arrays.toString(shake256));

        System.out.println(result);

        return new byte[][]{shake128, shake256};
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
     * @return the cryptogram (nonce || cyphertext)
     */
    public static byte[] encryptMode(File inFile, String passPhrase) {

        return null;
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
    public static byte[] decryptMode(File inFile, String passPhrase) {

        // check if MAC tag is included

        return null;
    }
}
