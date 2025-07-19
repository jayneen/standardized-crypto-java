class KECCAK_F {


    //TODO: ADJUST THIS TO BE A 3D ARRAY OF LENGTH 5X5X(64/BLOCKSIZETHINGY)
    private static byte[] MY_STATE;

    KECCAK_F(){}


    public static void permutate(final byte [] theState) {
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
        int laneLength = MY_STATE[0][0].length;

        byte[][] C = new byte [5][laneLength];
        byte[][] D = new byte [5][laneLength];

        //filling c with 0
        for(int x = 0; x < 5; x++)
        {
            for(int z = 0; z < 5; z++)
            {
                C[x][z] = 0;
            }
        }

        //Computing C[x][z]
        //C[x,z]=A[x, 0,z] ⊕ A[x, 1,z] ⊕ A[x, 2,z] ⊕ A[x, 3,z] ⊕ A[x, 4,z]
        for (int x = 0; x < 5; x++)
        {
            for(int y = 0; y < 5; y++)
            {
                for (int z = 0; z < laneLength; z++)
                {
                    C[x][z] ^= MY_STATE[x][y][z];
                }
            }
        }

        //Computing D[x][z]
        //D[x,z]=C[(x-1) mod 5, z] ⊕ C[(x+1) mod 5, (z –1) mod w].
        for(int x = 0; x < 5; x++)
        {
            for(int z = 0; z < laneLength; z++)
            {
                //(x+4)%5 equivalent (x-1)%5 and covers the wrap around
                //adding the laneLength to z at the end helps cover negative values as well
                D[x][z] = (byte) (C[(x + 4) % 5][z] ^ C[(x + 1) % 5][(z + laneLength- 1) % laneLength]);
            }
        }

        //Computing A'[x][y][z]
        //A′[x, y,z] = A[x, y,z] ⊕ D[x,z].
        for(int x = 0; x < 5; x++)
        {
            for(int y = 0; y < 5; y++)
            {
                for(int z = 0; z < laneLength; z++)
                {
                    MY_STATE[x][y][z] ^= D[x][z];
                }
            }
        }
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
