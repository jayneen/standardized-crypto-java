/**
 * Assignment 1
 * part: 1
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

    private boolean finalized = false;

    private int modeDomain = 0x1F;

    private int absorbPos = 0;

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
            absorbPos = 0;
            modeDomain = (suffix == 128 || suffix == 256) ? 0x1F : 0x06;
            finalized = false;
            SqueezeIterator = 0;
        } else {
            throw new InvalidParameterException("""
                    The SHA-3 security level must be either
                    224, 256, 384, or 512.
                    
                    The SHAKE security level must be either
                    128, or 256.
                    """);
        }

    }

    private void finalizeAbsorb() {
        if (!finalized) {
            int rate = MY_RATE / 8;
            MY_STATE[absorbPos] ^= (byte) modeDomain;
            MY_STATE[rate - 1] ^= (byte) 0x80;
            MY_STATE = KECCAK_F.permutate(MY_STATE);
            absorbPos = 0;
            finalized = true;
            SqueezeIterator = 0;
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
    public void absorb(byte[] data, int pos, int len) {
        int r = MY_RATE / 8;
        int i = 0;

        if (finalized) {
            throw new IllegalStateException("Cannot absorb after squeezing; call init() " +
                    "first!");
        }

        while (i < len) {
            int take = Math.min(r - absorbPos, len - i);
            for (int j = 0; j < take; j++) {
                MY_STATE[absorbPos + j] ^= data[pos + i + j];
            }
            absorbPos += take;
            i += take;
            if (absorbPos == r) {
                MY_STATE = KECCAK_F.permutate(MY_STATE);
                absorbPos = 0;
            }
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

        int rate = MY_RATE / 8;

        if (out.length < len) {
            throw new InvalidParameterException("The squeeze buffer is too small: need " + len + " bytes");
        }

        if (!finalized) {

            finalizeAbsorb();
        }

        int outIterator = 0;

        //Here we loop through our
        while (outIterator < len) {
            if (SqueezeIterator == rate) {

                MY_STATE = KECCAK_F.permutate(MY_STATE);

                SqueezeIterator = 0;
            }

            int chunk = Math.min(rate - SqueezeIterator, len - outIterator);

            //This nifty loop is copying over stuff from our state to our output buffer
            if (chunk > 0) {
                System.arraycopy(MY_STATE, SqueezeIterator, out, outIterator, chunk);
            }

            outIterator = chunk + outIterator;
            SqueezeIterator = chunk + SqueezeIterator;
        }

        return out;
    }

    @Override
    public byte[] squeeze(int len) {
        if (!finalized) {
            finalizeAbsorb();
        }
        byte[] out = new byte[len];
        return squeeze(out, len);
    }

    @Override
    public byte[] digest(byte[] out) {
        int suffix = (1600 - MY_RATE) / 2; // in bits
        return squeeze(out, suffix / 8);
    }

    @Override
    public byte[] digest() {
        int suffix = (1600 - MY_RATE) / 2; // in bits
        return squeeze(suffix / 8);
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

        if (len % 8 != 0) {
            throw new InvalidParameterException("The length must be a multiple of 8 bits");
        }

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
        int rate = MY_RATE / 8;
        int remainderBytes = theState.length % rate;

        // if remainderBytes is 0 set it as rate, else get the difference of rate and remainder
        int pad = (remainderBytes == 0) ? rate : (rate - remainderBytes);

        byte[] out = java.util.Arrays.copyOf(theState, theState.length + pad);

        out[theState.length] ^= (byte) theDomainCode;

        out[out.length - 1] ^= (byte) 0x80;

        return out;
    }

    private static byte[] getBytes(byte[] theState, int len, byte[] out,
                                   SHA3SHAKE sha3SHAKE) {

        sha3SHAKE.absorb(theState);

        sha3SHAKE.finalized = true;
        sha3SHAKE.absorbPos = 0;
        sha3SHAKE.SqueezeIterator = 0;

        if (out == null) {
            return sha3SHAKE.squeeze(len / 8);

        }
        sha3SHAKE.squeeze(out, len / 8);


        return out;
    }


}
