class KECCAK_F {


    private static byte[] MY_STATE;

    private static final long[] K_CONST = {1, 0x8082, 0x800000000000808aL, 0x8000000080008000L,
            0x808b, 0x80000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x8a, 0x88, 0x80008009L, 0x8000000aL,0x8000808bL, 0x800000000000008bL,
            0x8000000000008089L, 0x8000000000008003L,0x8000000000008002L,
            0x8000000000000080L, 0x800a, 0x800000008000000aL,0x8000000080008081L,
            0x8000000000008080L, 0x80000001L, 0x8000000080008008L};

    KECCAK_F() {}


    public static void permutate(final byte[] theState) {
        MY_STATE = theState;
        for (int i = 0; i < 24; i++) {
            theta();
            rho();
            pi();
            chi();
            iota(i);
        }
    }

    /**
     * MixColumns
     */
    private static void theta() {
        byte[] temp = MY_STATE;
    }

    /**
     * ShiftRows transform (Down columns' lane)
     */
    private static void rho() {
        byte[] temp = MY_STATE;
    }

    /**
     * ShiftRows transform
     */
    private static void pi() {
        byte[] temp = MY_STATE;
    }


    /**
     * SubBytes transform (bit left rotation with added nand gate)
     */
    private static void chi() {
        byte[] temp = MY_STATE;
    }

    /**
     * Add keccak constants (64-bits) to the bit (0,0) lane
     */
    private static void iota(final int counter) {
        MY_STATE[0] ^= (byte) K_CONST[counter];
    }

}
