
class KECCAK_F {


    private static final int[][][] MY_STATE = new int[5][5][64];

    KECCAK_F() {
    }


    public static byte[] permutate(final byte[] theState) {

        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                int laneIndex = 8 * (5 * y + x); // starting byte index for lane (x, y)
                for (int byteOffset = 0; byteOffset < 8; byteOffset++) {
                    byte laneByte = theState[laneIndex + byteOffset];
                    for (int bit = 0; bit < 8; bit++) {
                        int z = byteOffset * 8 + bit;
                        MY_STATE[x][y][z] = (byte) ((laneByte >>> bit) & 1);
                    }
                }
            }
        }

        for (int k = 0; k < 24; k++) {
            theta();
            rho();
            pi();
            chi();
            iota(k);
        }

        return flattenState();
    }

    /**
     * MixColumns
     */
    private static void theta() {
        int laneLength = MY_STATE[0][0].length;

        byte[][] C = new byte[5][laneLength];
        byte[][] D = new byte[5][laneLength];

        //filling c with 0
        for (int x = 0; x < 5; x++) {
            for (int z = 0; z < 5; z++) {
                C[x][z] = 0;
            }
        }

        //Computing C[x][z]
        //C[x,z]=A[x, 0,z] ⊕ A[x, 1,z] ⊕ A[x, 2,z] ⊕ A[x, 3,z] ⊕ A[x, 4,z]
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                for (int z = 0; z < laneLength; z++) {
                    C[x][z] ^= (byte) MY_STATE[x][y][z];
                }
            }
        }

        //Computing D[x][z]
        //D[x,z]=C[(x-1) mod 5, z] ⊕ C[(x+1) mod 5, (z –1) mod w].
        for (int x = 0; x < 5; x++) {
            for (int z = 0; z < laneLength; z++) {
                //(x+4)%5 equivalent (x-1)%5 and covers the wrap around
                //adding the laneLength to z at the end helps cover negative values as well
                D[x][z] = (byte) (C[(x + 4) % 5][z] ^ C[(x + 1) % 5][(z + laneLength - 1) % laneLength]);
            }
        }

        //Computing A'[x][y][z]
        //A′[x, y,z] = A[x, y,z] ⊕ D[x,z].
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                for (int z = 0; z < laneLength; z++) {
                    MY_STATE[x][y][z] ^= D[x][z];
                }
            }
        }
    }

    /**
     * ShiftRows transform (Down columns' lane)
     */
    private static void rho() {

    }

    /**
     * ShiftRows transform
     */
    private static void pi() {

    }


    /**
     * SubBytes transform (bit left rotation with added nand gate)
     */
    private static void chi() {

    }

    /**
     * Add keccak constants (64-bits) to the bit (0,0) lane
     */
    private static void iota(final int counter) {
        final long[] k_const = {1L, 0x8082L, 0x800000000000808aL, 0x8000000080008000L,
                0x808bL, 0x80000001L, 0x8000000080008081L, 0x8000000000008009L,
                0x8aL, 0x88L, 0x80008009L, 0x8000000aL, 0x8000808bL, 0x800000000000008bL,
                0x8000000000008089L, 0x8000000000008003L,
                0x8000000000008002L, 0x8000000000000080L, 0x800aL, 0x800000008000000aL,
                0x8000000080008081L, 0x8000000000008080L, 0x80000001L, 0x8000000080008008L};

        long k_const_1 = k_const[counter];

        for(int i = 0; i < 64; i++) {
            MY_STATE[0][0][i] ^= (int) ((k_const_1 >>> i) & 1);
        }

    }

    private static byte[] flattenState() {
        byte[] flatState = new byte[200]; // 25 lanes × 8 bytes = 200 bytes

        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                int laneStartIndex = 8 * (5 * y + x); // start index for lane (x, y)

                for (int byteOffset = 0; byteOffset < 8; byteOffset++) {
                    int zBase = byteOffset * 8;
                    byte b = 0;

                    for (int bit = 0; bit < 8; bit++) {
                        int z = zBase + bit;
                        b |= (byte) ((KECCAK_F.MY_STATE[x][y][z] & 1) << bit); // pack bits LSB-first
                    }

                    flatState[laneStartIndex + byteOffset] = b;
                }
            }
        }

        return flatState;
    }

}
