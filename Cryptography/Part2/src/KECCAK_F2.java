/**
 * Assignment 1
 * part: 2
 *
 * This is a retrofitted version of Markku-Juhani O. Saarinen original C implementation,
 * but converted to Java. All credit goes to Saarinen, all we did was adjust it slightly
 * to work properly. Original implementation can be found here:
 *
 * <a href="https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c">...</a>
 *
 * @author Markku-Juhani O. Saarinen <mjos@iki.fi>, Kassie Whitney, Zane Swaims, Evgeniia Nemynova
 * @version 7.19.25
 * Previous Version: 19-Nov-11
 * Revised 07-Aug-15 to match with official release of FIPS PUB 202 "SHA3"
 * Revised 03-Sep-15 for portability + OpenSSL - style API
 */

public class KECCAK_F2 {
    private static final int KECCAKF_ROUNDS = 24;

    //Constants
    private static final long[] keccakf_rndc = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private static final int[] keccakf_rotc = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55,
            2, 14, 27, 41, 56, 8, 25, 43, 62, 18,
            39, 61, 20, 44
    };

    private static final int[] keccakf_piln = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21,
            24, 4, 15, 23, 19, 13, 12, 2, 20, 14,
            22, 9, 6, 1
    };

    protected long[] state = new long[25];
    private byte[] buffer;
    private int rate;
    private int capacity;
    private int outputLength;
    private int bufferPos;

    //Full constructor (depreciated)
    public KECCAK_F2(int outputBits) {
        this.outputLength = outputBits / 8;
        this.capacity = outputBits * 2;
        this.rate = 200 - (capacity / 8);
        this.buffer = new byte[rate];
        this.bufferPos = 0;
    }

    //Minimal constructor for permutation use only
    public KECCAK_F2() {
        //No buffer/rate setup needed for standalone permutation
    }

    private static long rotl(long x, int n) {
        return (x << n) | (x >>> (64 - n));
    }

    private void keccakf2() {
        long[] bc = new long[5];
        long t;

        for (int round = 0; round < KECCAKF_ROUNDS; round++) {

            //Theta
            for (int i = 0; i < 5; i++) {
                bc[i] = state[i] ^ state[i + 5] ^ state[i + 10]
                        ^ state[i + 15] ^ state[i + 20];
            }
            for (int i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ rotl(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) {
                    state[j + i] ^= t;
                }
            }


            //Rho and Pi
            t = state[1];
            for (int i = 0; i < 24; i++) {
                int j = keccakf_piln[i];
                bc[0] = state[j];
                state[j] = rotl(t, keccakf_rotc[i]);
                t = bc[0];
            }

            //Chi
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++) bc[i] = state[j + i];
                for (int i = 0; i < 5; i++) {
                    state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }

            //Iota
            state[0] ^= keccakf_rndc[round];
        }
    }

    //(Depreciated)
    public void update(byte[] input) {
        for (byte b : input) {
            buffer[bufferPos++] ^= b;
            if (bufferPos == rate) {
                absorbBlock();
                bufferPos = 0;
            }
        }
    }

    private void absorbBlock() {
        for (int i = 0; i < rate / 8; i++) {
            state[i] ^= toLongLE(buffer, i * 8);
        }
        keccakf2();
    }

    /**
     * Conversion method, Byte to Long
     *
     * @param buf     the byte array containing the data
     * @param offset    the starting index in the buffer
     * @return the {@code long} value represented by the 8 bytes
     */
    protected long toLongLE(byte[] buf, int offset) {
        return ((long) buf[offset] & 0xFF) |
                (((long) buf[offset + 1] & 0xFF) << 8) |
                (((long) buf[offset + 2] & 0xFF) << 16) |
                (((long) buf[offset + 3] & 0xFF) << 24) |
                (((long) buf[offset + 4] & 0xFF) << 32) |
                (((long) buf[offset + 5] & 0xFF) << 40) |
                (((long) buf[offset + 6] & 0xFF) << 48) |
                (((long) buf[offset + 7] & 0xFF) << 56);
    }

    /**
     * Conversion method, Long to Byte
     *
     * @param value the {@code long} value to convert
     * @param output the byte array to write the result into
     * @param offset the starting index in the output array
     */
    private static void longToBytesLE(long value, byte[] output, int offset) {
        output[offset] = (byte) (value);
        output[offset + 1] = (byte) (value >>> 8);
        output[offset + 2] = (byte) (value >>> 16);
        output[offset + 3] = (byte) (value >>> 24);
        output[offset + 4] = (byte) (value >>> 32);
        output[offset + 5] = (byte) (value >>> 40);
        output[offset + 6] = (byte) (value >>> 48);
        output[offset + 7] = (byte) (value >>> 56);
    }

    /**
     * Static method to apply Keccak-f permutation to a 200-byte state.
     * The input must be exactly 200 bytes (i.e., 1600 bits), which corresponds
     * to the state size of the Keccak-f[1600] permutation used in SHA-3 and SHAKE.
     *
     * @param input a 200-byte array representing the state before permutation
     * @return a new 200-byte array representing the permuted state
     * @throws IllegalArgumentException if the input is not 200 bytes long
     */
    public static byte[] permutate(byte[] input) {
        if (input.length != 200)
            throw new IllegalArgumentException("State must be 200 bytes");

        KECCAK_F2 kf = new KECCAK_F2();

        //Load the state from input
        for (int i = 0; i < 25; i++) {
            kf.state[i] = kf.toLongLE(input, i * 8);
        }

        //Perform permutation
        kf.keccakf2();

        //Convert back to byte array
        byte[] output = new byte[200];
        for (int i = 0; i < 25; i++) {
            longToBytesLE(kf.state[i], output, i * 8);
        }

        return output;
    }
}