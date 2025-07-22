import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;
import java.util.Arrays;

/**
 * Assignment 1
 * part: 1
 *
 * @author Kassie Whitney, Zane Swaims, Evgeniia Nemynova
 * @version 7.19.25
 */

public class SHA3SHAKE extends KECCAK_F implements SHA3SHAKE_INTERFACE {

    /**
     * The Current State binary array
     */
    private byte[] MY_STATE;

    /**
     * The size of the partition from the plain text message.
     * <p>
     * Formula: RATE = (1600-bits) - ((CAPACITY(suffix * 2))-bits)
     * </P>
     */
    private int MY_RATE;

    private int SqueezeIterator;

    public SHA3SHAKE() {
        SqueezeIterator = 0;
    }

    @Override
    public void init(int suffix) {

        if (suffix == 128 || suffix == 224 || suffix == 256 || suffix == 384 || suffix == 512) {

            MY_RATE = 1600 - (suffix * 2);
            MY_STATE = new byte[200];

        } else {
            throw new InvalidParameterException("""
                    The SHA-3 security level must be either
                    224, 256, 384, or 512.
                    
                    The SHAKE security level must be either
                    128, or 256.
                    """);
        }

    }

    /**
     * The sponge
     *
     * @param data byte-oriented data buffer (an arbitrary length)
     * @param pos  initial index to hash from
     * @param len  byte count on the buffer
     */
    @Override
    public void absorb(final byte[] data, final int pos, final int len) {

        int newPos = pos;
        int newLen = len;
        int rateBytes = MY_RATE / 8;

        while (newLen > 0) {
            int messageChunkSize = Math.min(rateBytes, newLen);

            for (int i = 0; i < messageChunkSize; i++) {
                MY_STATE[i] ^= data[newPos + i];
            }

            if (messageChunkSize == rateBytes) {
                MY_STATE = KECCAK_F.permutate(MY_STATE);
            }

            newPos += messageChunkSize;
            newLen -= messageChunkSize;

        }
    }

    @Override
    public void absorb(byte[] data, int len) {
        absorb(data, 0, len);
    }

    @Override
    public void absorb(byte[] data) {
        absorb(data, 0, data.length);
    }

    @Override
    public byte[] squeeze(byte[] out, int len) {
        int outIterator = 0;

        //Here we loop through our
        while (outIterator < len) {
            if (SqueezeIterator == MY_RATE / 8) {

                MY_STATE = KECCAK_F.permutate(MY_STATE);

                SqueezeIterator = 0;
            }

            int chunk = Math.min(MY_RATE / 8 - SqueezeIterator, len - outIterator);

            //This nifty loop is copying over stuff from our state to our output buffer
            if (chunk >= 0) {
                System.arraycopy(MY_STATE, SqueezeIterator, out, outIterator, chunk);
            }

            outIterator = chunk + outIterator;
            SqueezeIterator = chunk + SqueezeIterator;
        }

        return out;
    }

    @Override
    public byte[] squeeze(int len) {
        byte[] out = new byte[len];
        return squeeze(out, len);
    }

    @Override
    public byte[] digest(byte[] out) {
        int suffix = (1600 - MY_RATE) / 2;
        return squeeze(out, suffix);
    }

    @Override
    public byte[] digest() {
        int suffix = (1600 - MY_RATE) / 2;
        return squeeze(suffix);
    }

    /**
     * Compute the streamlined SHA-3-<224,256,384,512> on input theState.
     * <p>
     * Static Method.
     * <p>
     *
     * @param theSuffix desired output length in bits (one of 224, 256, 384, 512)
     * @param theState  data to be hashed
     * @param out       hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHA3(int theSuffix, byte[] theState, byte[] out) {

        if (theSuffix != 224 && theSuffix != 256 && theSuffix != 384 && theSuffix != 512) {
            throw new IllegalArgumentException("Invalid suffix!");
        }
        SHA3SHAKE sha3SHAKE = new SHA3SHAKE();
        sha3SHAKE.init(theSuffix);
        theState = PADDING(theState, 0x06, sha3SHAKE.MY_RATE);
        return getBytes(theState, theSuffix, out, sha3SHAKE);
    }


    /**
     * Compute the streamlined SHAKE-<128,256> on input theState with output bit-length len.
     * <p>
     * Static Method.
     * <p>
     *
     * @param theSuffix desired security level (either 128 or 256)
     * @param theState  data to be hashed
     * @param len       desired output length in bits (must be a multiple of 8)
     * @param out       hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    static byte[] SHAKE(int theSuffix, byte[] theState, int len, byte[] out) {

        if (theSuffix != 128 && theSuffix != 256) {
            throw new IllegalArgumentException("Invalid suffix!");
        }

        SHA3SHAKE sha3SHAKE = new SHA3SHAKE();
        sha3SHAKE.init(theSuffix);
        theState = PADDING(theState, 0x1F, sha3SHAKE.MY_RATE);
        return getBytes(theState, len, out, sha3SHAKE);
    }


    /**
     * Pads the remaining bytes that are less than the rate in bytes within accordance to the
     * SHA3 and SHAKE padding requirements.
     *
     * @param theState      The message from the user.
     * @param theDomainCode either 0x06 (SHA3) or 0x1F (SHAKE)
     * @return The modified message with the added padding.
     */
    private static byte[] PADDING(byte[] theState, final int theDomainCode, final int MY_RATE) {
        byte[] temp;

        if (theState.length < MY_RATE / 8) {
            temp = new byte[200];
            System.arraycopy(theState, 0, temp, 0, theState.length);

            //adds 00000110 to the end of the theState message (domain)
            temp[theState.length] = (byte) theDomainCode;

            // adds 10000000 to the end of the temp array (padding)
            temp[(MY_RATE / 8) - 1] |= (byte) 0x80;

            // set theState as temp
            theState = temp;

        } else if (theState.length > MY_RATE / 8) {
            temp = new byte[200];//will hold the last chunk that needs padding

            //The number of complete chunks of size rate (byte)
            int startPos = theState.length - (theState.length % (MY_RATE / 8));
            //The number of bytes remaining that's less than the rate (byte)
            int numOfRemainBytes = theState.length % (MY_RATE / 8);

            System.arraycopy(theState, startPos, temp, 0, numOfRemainBytes);

            //The padding
            temp[numOfRemainBytes] = (byte) theDomainCode;
            temp[(MY_RATE / 8) - 1] |= (byte) 0x80;

            // The length of the buffer will be the length of the state + the extra padding
            // The buffer will combine the padded chunk plus the message.
            byte[] buffer = new byte[theState.length + (MY_RATE / 8)];

            //Adds content from theState to the buffer.
            System.arraycopy(theState, 0, buffer, 0, theState.length);

            //Adds the padded content from temp into the buffer
            System.arraycopy(temp, 0, buffer, startPos, MY_RATE / 8);

            theState = buffer;

        } else {
            temp = new byte[MY_RATE / 8];
            temp[0] = (byte) theDomainCode;
            temp[temp.length - 1] = (byte) 0x80;
            byte[] buffer = new byte[temp.length + theState.length];

            System.arraycopy(theState, 0, buffer, 0, theState.length);
            System.arraycopy(temp, 0, buffer, theState.length, temp.length);

            theState = buffer;

        }

        return theState;
    }


    private static byte[] getBytes(byte[] theState, int len, byte[] out,
                                   SHA3SHAKE sha3SHAKE) {
        //TODO:REMOVE ME
        System.out.println("Padded input:");
        for (int i = 0; i < theState.length; i++) {
            System.out.printf("%02x ", theState[i]);
        }
        System.out.print("\n");
        sha3SHAKE.absorb(theState);

        if (out == null) {
            out = sha3SHAKE.squeeze(len / 8);

        } else {
            sha3SHAKE.squeeze(out, len / 8);

        }


        return out;
    }

    //TODO: TESTING MAIN
    public static void main(String[] args) {
        // Example string to hash
        String message = "abc";
        // Convert to bytes
        byte[] input = message.getBytes(StandardCharsets.UTF_8);

        // Call the static SHA3 method with 256-bit suffix
       byte[] hash = SHA3(256, input, null);  // SHA3-256

        // Print the result in hex
        System.out.println("SHA3-256 hash:");
        for (byte b : hash) {
            System.out.printf("%02x", b);
        }
        System.out.println();
    }


}
