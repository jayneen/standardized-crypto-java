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

    public static void main(String[] args) {
        Scanner input;

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

            byte[] fileBinary;
            byte[] passBinary;

            input = new Scanner(System.in);

            try {
                System.out.println("\nSHA-3/SHAKE encryption");

                System.out.print("Please enter a security level for SHA-3 (224,256,384,512) " +
                        "> ");
                final int ShaSecLevel = Integer.parseInt(input.nextLine());

                System.out.print("\n\nPlease enter a security level for SHAKE (128,256) > ");

                final int ShakeSecLevel = Integer.parseInt(input.nextLine());

                if (userInput == null) {
                    System.out.print("Please enter the files path (Q to quit) > ");
                    userInput = input.nextLine().replace("\"", "");

                    if (userInput.equalsIgnoreCase("q")) {
                        input.close();
                        break;
                    }
                }

                // Getting users passphrase and document path
                fileBinary = Files.readAllBytes(Paths.get(userInput));
                fileSize(fileBinary);

                if (passphrase == null) {
                    System.out.println("Please enter a passphrase: ");
                    passphrase = input.nextLine();
                }

                passBinary = passphrase.getBytes(StandardCharsets.UTF_8);
                System.out.println("Total KiB read: " + (double) passBinary.length / 1025 +
                        "\n");

                // outputting the sample document binary file.
                final byte[] docSample = new byte[10];
                System.arraycopy(fileBinary, 0, docSample, 0, docSample.length);
                System.out.println("Previous file Hash: " + Arrays.toString(docSample));

                // calling SHA3/SHAKE
                passBinary = SHA3SHAKE.SHAKE(ShakeSecLevel, passBinary, ShaSecLevel,
                        null);
                fileBinary = SHA3SHAKE.SHA3(ShaSecLevel, fileBinary, null);

                // Outputting sample size Hashed document
                final byte[] encryptedFile = encryptFile(passBinary, fileBinary);

                System.arraycopy(encryptedFile, 0, docSample, 0, docSample.length);

                System.out.println("Post Encrypted: " + Arrays.toString(docSample));

                fileSize(encryptedFile);

                if (userOutput == null) {

                    // Creating a new file recursively
                    final File finalDocument = checkFile(new File("EncryptedFile.txt"));
                    convertToHexAndWrite(finalDocument, encryptedFile);

                } else {

                    // if the name is provided through command line arguments, create and overwrite
                    // it
                    final File finalDocument = new File(userOutput);
                    Files.write(finalDocument.toPath(), encryptedFile, StandardOpenOption.CREATE);

                }

            } catch (InvalidPathException | IOException invalidPathException) {

                System.out.println("""
                        This is an invalid file path or the file is unable to convert to binary!
                        Please try again!
                        """);

            }
        }
    }

    /**
     * Prints the size of the file or passphrase for informational purposes.
     *
     * @param encryptedFile the file or passphrase in byte[]
     */
    private static void fileSize(byte[] encryptedFile) {

        if (encryptedFile.length < 1024) {

            System.out.println("Total Bytes read: " + (double) encryptedFile.length);

        } else if (1025 <= encryptedFile.length && encryptedFile.length < 1_048_576) {

            System.out.println("Total KiB read: " + (double) encryptedFile.length / 1025);

        } else if (1_048_576 <= encryptedFile.length) {

            System.out.println("Total MiB read: " + (double) encryptedFile.length / 1_048_576);
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
     * Handles the first task of hashing a user specified file
     * using SHA-3-256 and -512 (bonus: -224, 384).
     * 
     * @param inFile user specified input file
     * @param outFile user specified output file
     * @return all computed hashes
     */
    public static String hashMode(File inFile, File outFile) {
        
        // call all 4 hashes or prompt for just 1 at a time

        return null;
    }

    /**
     * Handles the second task of creating MAC tags of user specified length
     * for a user specified file and under a user specified pass phrase
     * using SHAKE-128 and -256 (bonus: compute tags for direct text input).
     * 
     * @param inFile user specified input file
     * @param outFile user specified output file
     * @param passPhrase user specified pass phrase
     * @return all computed tags
     */
    public static String tagMode(File inFile, File outFile, String passPhrase) {
        
        // check if inFile exists
        // if not treat it as direct input

        return null;
    }

    /**
     * Handles the third task of ecnrypting a user specified file under
     * the user specified pass phrase by:
     * 1) hashing the pass phrase with SHAKE-128 as the key
     * 2) obtaining a random 128-bit nonce
     * 3) hashing the nonce and the data file using SHAKE-128 as a stream cipher
     * (bonus: include a MAC tag using SHA-3-256 and the same key)
     * 
     * @param inFile user specified input file
     * @param outFile user specified output file
     * @param passPhrase user specified pass phrase
     * @return the cryptogram (nonce || cyphertext)
     */
    public static String encryptMode(File inFile, File outFile, String passPhrase) {

        return null;
    }

    /**
     * Handles the fourth task of decrypting a user specified file under
     * the user specified pass phrase using SHAKE-128 and the supplied nonce.
     * (bonus: verify the MAC tag if included)
     * 
     * @param inFile user specified input file
     * @param outFile user specified output file
     * @param passPhrase user specified pass phrase
     * @return decrypted message
     */
    public static String decryptMode(File inFile, File outFile, String passPhrase) {

        // check if MAC tag is included

        return null;
    }
}
