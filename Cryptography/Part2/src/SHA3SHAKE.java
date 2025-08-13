/**
 * Assignment 1
 * part: 1
 * 
 * This is an implementation of a cryptographic sponge used in SHA-3 and SHAKE algorithms
 * that utilizes Keccak permutations to encrypt data, compute hashes, and generate tags.
 *
 * @author Kassie Whitney, Zane Swaims, Evgeniia Nemynova
 * @version 7.29.25
 */

import java.security.InvalidParameterException;


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
        int rateBytes = MY_RATE / 8; // Get the rate in bytes

        // Case 1: Message is shorter than one full rate block
        if (theState.length < rateBytes) {
            // Create a buffer for the current message bytes + padding to fill the rate block
            byte[] paddedBlock = new byte[rateBytes];

            System.arraycopy(theState, 0, paddedBlock, 0, theState.length); // Copy original message bytes

            paddedBlock[theState.length] = (byte) theDomainCode; // Append 0x06 (or 0x1F)

            paddedBlock[rateBytes - 1] |= (byte) 0x80; // Append 0x80 to the last byte of the rate block

            return paddedBlock; // Return this single padded block
        }
        // Case 2: Message extends beyond full rate blocks, or exactly fills a block
        else {
            int numOfRemainBytes = theState.length % rateBytes;

            // If the message perfectly fills current blocks, we need to append a full new padding block.
            if (numOfRemainBytes == 0) {
                numOfRemainBytes = rateBytes; // We'll create a full block of padding
            }

            // Create a temporary buffer to hold the last partial block + padding
            byte[] tempPaddingBlock = new byte[rateBytes]; // Always create a full block for padding

            // Copy the remaining bytes from the original message (if any) into the temp padding block
            System.arraycopy(theState, theState.length - numOfRemainBytes, tempPaddingBlock, 0, numOfRemainBytes);

            tempPaddingBlock[numOfRemainBytes] = (byte) theDomainCode; // Append 0x06 (or 0x1F)
            tempPaddingBlock[rateBytes - 1] |= (byte) 0x80; // Append 0x80 to the last byte of the rate block

            // Now, combine the original full blocks (if any) with this new padded block
            // The total length will be original_length_minus_remainder + new_padded_block_length
            byte[] finalPaddedState = new byte[theState.length - numOfRemainBytes + rateBytes];

            // Copy original full blocks
            System.arraycopy(theState, 0, finalPaddedState, 0, theState.length - numOfRemainBytes);

            // Copy the newly created padded block
            System.arraycopy(tempPaddingBlock, 0, finalPaddedState, theState.length - numOfRemainBytes, rateBytes);

            return finalPaddedState;
        }
    }

    private static byte[] getBytes(byte[] theState, int len, byte[] out,
                                   SHA3SHAKE sha3SHAKE) {

        sha3SHAKE.absorb(theState);

        if (out == null) {
            out = sha3SHAKE.squeeze(len / 8);

        } else {
            sha3SHAKE.squeeze(out, len / 8);

        }


        return out;
    }

}
