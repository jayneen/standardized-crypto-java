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

            byte[] fileBinary;
            byte[] passBinary;


            try {
                // select program mode or quit
                String userMode;
                System.out.print(
                        "Select an application mode:\n"
                                + "1 - to compute hashes\n"
                                + "2 - to compute tags\n"
                                + "3 - to encrypt a file\n"
                                + "4 - to decrypt a file\n"
                                + "Q - to quit the program)\n> ");
                userMode = input.nextLine().replace("\"", "");
                if (userMode.equalsIgnoreCase("q")) {
                    input.close();
                    break;
                }

                // TODO Verify input file
                assert userInput != null;
                File inputFile = new File(userInput);

                // Apply mode
                String result;
                switch (userMode) {
                    case "1":
                        result = Arrays.toString(hashMode(inputFile));
                        break;
                    case "2":
                        passphrase = validatePassphrase(input, passphrase);
                        result = Arrays.toString(tagMode(inputFile, passphrase));
                        break;
                    case "3":
                        passphrase = validatePassphrase(input, passphrase);
                        result = encryptMode(inputFile, passphrase);
                        break;
                    case "4":
                        passphrase = validatePassphrase(input, passphrase);
                        result = decryptMode(inputFile, passphrase);
                        break;
                    default:
                        System.out.println("Invalid mode entered. Please select a valid mode.");
                        continue; // restart the while loop
                }

                // TODO converge modes to write output and refactor the old code


                // old main code

                System.out.println("\nSHA-3/SHAKE encryption");

                System.out.print("Please enter a security level for SHA-3 (224,256,384,512) " +
                        "> ");
                final int ShaSecLevel = Integer.parseInt(input.nextLine());

                System.out.print("\n\nPlease enter a security level for SHAKE (128,256) > ");

                final int ShakeSecLevel = Integer.parseInt(input.nextLine());

                passBinary = passphrase.getBytes(StandardCharsets.UTF_8);
                System.out.println("Total KiB read: " + (double) passBinary.length / 1025 +
                        "\n");

                // Process the document path
                fileBinary = Files.readAllBytes(Paths.get(userInput));
                fileSize(fileBinary);

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

    public static String validatePassphrase(Scanner input, String passphrase) {
        if (passphrase == null) {
            System.out.println("Please enter a passphrase: ");
            passphrase = input.nextLine();
        }
        return passphrase;
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

        if (inFile == null) {

            System.out.print("\n\nPlease enter a message: > ");
            String message = input.nextLine();

            System.out.print("\n\nPlease designate the length of your MACs tag > ");

            len = Integer.parseInt(String.valueOf(input.nextLine()));

            byte[] msgByte = message.getBytes(StandardCharsets.UTF_8);
            byte[] thePass = passPhrase.getBytes(StandardCharsets.UTF_8);
            kMac = new byte[thePass.length + msgByte.length];

            System.arraycopy(thePass, 0, kMac, 0, thePass.length);
            System.arraycopy(msgByte, 0, kMac, thePass.length, msgByte.length);

        } else {

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
        }

        if(kMac.length == 0 || len == 0) {
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
    public static String encryptMode(File inFile, String passPhrase) {

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
    public static String decryptMode(File inFile, String passPhrase) {

        // check if MAC tag is included

        return null;
    }
}
