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

        while (true) {

            byte[] fileBinary;
            byte[] passBinary;

            Scanner input = new Scanner(System.in);
            try {
                System.out.println("\nSHA-3/SHAKE encryption");

                System.out.print("Please enter a security level for SHA-3 (224,256,384,512) " +
                        "> ");
                int ShaSecLevel = input.nextInt();

                System.out.print("\n\nPlease enter a security level for SHAKE (128,256) > ");

                int ShakeSecLevel = input.nextInt();

                System.out.print("Please enter the files path (Q to quit) > ");

                String userInput = input.nextLine().replace("\"", "");

                if (userInput.equalsIgnoreCase("q")) {
                    break;
                }

                //Getting users passphrase and document path
                fileBinary = Files.readAllBytes(Paths.get(userInput));
                fileSize(fileBinary);
                System.out.println("Please enter a passphrase: ");
                String passphrase = input.nextLine();
                passBinary = passphrase.getBytes(StandardCharsets.UTF_8);
                System.out.println("Total KiB read: " + (double) passBinary.length / 1025 +
                        "\n");

                //outputting the sample document binary file.
                byte[] docSample = new byte[10];
                System.arraycopy(fileBinary, 0, docSample, 0, docSample.length);
                System.out.println("Previous file Hash: " + Arrays.toString(docSample));

                // calling SHA3/SHAKE
                passBinary = SHA3SHAKE.SHAKE(ShakeSecLevel, passBinary, fileBinary.length,
                        null);
                fileBinary = SHA3SHAKE.SHA3(ShaSecLevel, fileBinary, null);

                // Outputting sample size Hashed document
                byte[] encryptedFile = encryptFile(passBinary, fileBinary);
                System.arraycopy(encryptedFile, 0, docSample, 0, docSample.length);
                System.out.println("Post Encrypted: " + Arrays.toString(docSample));
                fileSize(encryptedFile);

                //Creating a new file recursively
                File finalDocument = checkFile(new File("Encryptedfile.txt"));
                Files.write(finalDocument.toPath(), encryptedFile, StandardOpenOption.APPEND);


            } catch (InvalidPathException | IOException invalidPathException) {
                System.out.println("""
                        This is an invalid file path or the file is unable to convert to binary!
                        Please try again!
                        """);

            }
        }
    }

    /**
     * Gets the size of the file or passphrase for informational purposes.
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
     * @param theFile the file that will store the encrypted document
     * @return the newly generated file to be writen on.
     */
    private static File checkFile(File theFile) {
        try {
            if(!theFile.createNewFile()) {
                checkFile(theFile, 1);
            }
        } catch (final IOException ioException) {
            System.out.println("Unable to create new file!");
        }

        return theFile;
    }

    /**
     * Recursively checks if the file already exists and creates a new file.
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
     * @param theHashedPassPhrase the user chosen passphrase *Hash length must equal to the
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
        byte[] encryptedMessage = new byte[theHashedDocument.length];
        for (int i = 0; i < theHashedDocument.length; i++) {

            encryptedMessage[i] = (byte) (theHashedPassPhrase[i] ^ theHashedDocument[i]);
        }

        return encryptedMessage;
    }
}
