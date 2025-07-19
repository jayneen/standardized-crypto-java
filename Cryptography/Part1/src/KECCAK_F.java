class KECCAK_F {


    private static byte[] MY_STATE;

    KECCAK_F(){}


    public static void permutate(final byte[] theState) {
        MY_STATE = theState;
        for(int i = 0; i < 24; i++) {
            theta();
            rho();
            pi();
            chi();
            iota();
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
    private static void iota() {
         byte[] temp = MY_STATE;
    }

}
