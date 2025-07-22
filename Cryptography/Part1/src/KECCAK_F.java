
class KECCAK_F {


    private static int[][][] MY_STATE = new int[5][5][64];

    //hard coding the deterministic nature of rho
    private static final int[][] RHO_OFFSETS = {
            {  0,  36,   3, 105, 210 },
            {  1,  44,  10,  45,  66 },
            { 62,   6,  43,  15, 253 },
            { 28,  55,  25,  21, 120 },
            { 91, 276, 136,  78,  63 }
    };

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
//TODO: LOGIC SUGGESTED BY CHATGPT
//        for (int y = 0; y < 5; y++) {
//            for (int x = 0; x < 5; x++) {
//                int laneStart = 8 * (5 * y + x); // Correct byte offset
//                for (int z = 0; z < 64; z++) {
//                    int byteIndex = laneStart + (z / 8);
//                    int bitIndex = z % 8;
//                    int bit = (theState[byteIndex] >>> bitIndex) & 1;
//                    MY_STATE[x][y][z] = bit;
//                }
//            }
//        }

        for (int i = 0; i < 24; i++) {
            theta();
            rho();
            pi();
            chi();
            iota(i);
        }

        return flattenState();
    }

    /**
     * MixColumns
     */
    private static void theta() {
        int laneLength = MY_STATE[0][0].length;

        int[][] C = new int[5][laneLength];
        int[][] D = new int[5][laneLength];

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
                    C[x][z] ^= MY_STATE[x][y][z];
                }
            }
        }

        //Computing D[x][z]
        //D[x,z]=C[(x-1) mod 5, z] ⊕ C[(x+1) mod 5, (z –1) mod w].
        for (int x = 0; x < 5; x++) {
            for (int z = 0; z < laneLength; z++) {
                //(x+4)%5 equivalent (x-1)%5 and covers the wrap around
                //adding the laneLength to z at the end helps cover negative values as well
                D[x][z] = (C[(x + 4) % 5][z] ^ C[(x + 1) % 5][(z + laneLength - 1) % laneLength]);
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
//    private static void rho()
//    {
//        int laneLength = MY_STATE[0][0].length;
//        int[][][] myStateStar = new int[5][5][laneLength];
//
//        //For all z such that 0≤z<w, let A′ [0, 0,z] = A[0, 0,z]
//        for (int z = 0; z < laneLength; z++) {
//            myStateStar[0][0][z] = MY_STATE[0][0][z];
//        }
//
//        //Let (x, y) = (1, 0).
//        int x = 1;
//        int y = 0;
//
//        //3. For t from 0 to 23:
//        //a. for all z such that 0≤z<w, let A′[x, y,z] = A[x, y, (z–(t+1)(t+2)/2) mod w];
//        //b. let (x, y) = (y, (2x+3y) mod 5).
//        for(int t = 0; t < 24; t++)
//        {
//            int offset = ((t + 1) * (t + 2 )) / 2;
//            int offsetModed = offset % laneLength;
//
//            //complicated shit
//            for(int z = 0; z < laneLength; z++)
//            {
//                //to help prevent out of bounds i am just moding a bunch, trust it makes sense
//                int index = ((z - offsetModed) % laneLength + laneLength) % laneLength;
//
//                myStateStar[x][y][z] = MY_STATE[x][y][index];
//            }
//
//            int newX = y;
//            int newY = (2 * x + 3 * y) % 5;
//            x = newX;
//            y = newY;
//        }
//
//        //4. Return A′
//        //I'm upset at having to use i and j instead of x and y but those are being used already
//        for(int i = 0; i < 5; i++)
//        {
//            for(int j = 0; j < 5; j++)
//            {
//                for (int z = 0; z < laneLength; z++) {
//                    MY_STATE[i][j][z] = myStateStar[i][j][z];
//                }
//            }
//        }
//    }

//    //TODO: NEW LOGIC SUGGESTED BY CHAT GPT
//    private static void rho() {
//        int[][][] newState = new int[5][5][64];
//
//        for (int x = 0; x < 5; x++) {
//            for (int y = 0; y < 5; y++) {
//                int offset = RHO_OFFSETS[x][y];
//
//                for (int z = 0; z < 64; z++) {
//                    newState[x][y][z] = MY_STATE[x][y][(z + offset) % 64];
//                }
//            }
//        }
//
//        MY_STATE = newState;
//    }

    private static void rho() {
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                int offset = RHO_OFFSETS[x][y];

                // Step 1: Pack the 64 bits into a long
                long lane = 0L;
                for (int z = 0; z < 64; z++) {
                    lane |= ((long) MY_STATE[x][y][z] & 1L) << z;
                }

                // Step 2: Rotate
                long rotatedLane = Long.rotateLeft(lane, offset);

                // Step 3: Unpack the long back into 64 bits
                for (int z = 0; z < 64; z++) {
                    MY_STATE[x][y][z] = (int) ((rotatedLane >>> z) & 1L);
                }
            }
        }
    }

    //TODO: FIDDLE WITH THIS
    //pulled from https://github.com/aelstad/keccakj/blob/master/src/main/java/com/github/aelstad/keccakj/core/Keccak1600.java
    /*
    final static int index(int x, int y)
	{
		return (((x)%5)+5*((y)%5));
	}

	final static long rol64(long l, int offset) {
		return Long.rotateLeft(l, offset);
	}

    final void rho()
	{
	    int x, y;

	    for(x=0; x<5; x++) for(y=0; y<5; y++)
	        state[index(x, y)] = rol64(state[index(x, y)], KeccakRhoOffsets[index(x, y)]);
	}
     */

    /**
     * ShiftRows transform
     */
//    private static void pi() {
//        int[][][] buffer = new int[5][5][64];
//        for(int x = 0; x < 5; x++) {
//            for(int y = 0; y < 5; y++) {
//                System.arraycopy(MY_STATE[(x + 3 * y) % 5][x], 0, buffer[x][y], 0, 64);
//            }
//        }
//
//        MY_STATE = buffer;
//    }

    //TODO: THIS SHOULD WORK ACCORDING TO CHAT GPT
    private static void pi() {
        int[][][] buffer = new int[5][5][64];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                for (int z = 0; z < 64; z++) {
                    buffer[y][(2 * x + 3 * y) % 5][z] = MY_STATE[x][y][z];
                }
            }
        }
        MY_STATE = buffer;
    }



    /**
     * SubBytes transform (bit left rotation with added nand gate)
     */
    private static void chi() {
        for(int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                for(int z = 0; z < 64; z++) {
                    MY_STATE[x][y][z] ^= ((MY_STATE[(x+1)%5][y][z] ^ 1) * MY_STATE[(x+2)%5][y][z]);
                }
            }
        }
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

    //TODO: THIS SHOULD WORK ACCORDING TO CHAT GPT
//    private static byte[] flattenState() {
//        byte[] flatState = new byte[200];
//
//        for (int y = 0; y < 5; y++) {
//            for (int x = 0; x < 5; x++) {
//                for (int b = 0; b < 8; b++) {
//                    byte value = 0;
//                    for (int bit = 0; bit < 8; bit++) {
//                        value |= (MY_STATE[x][y][b * 8 + bit] & 1) << bit;
//                    }
//                    flatState[8 * (5 * y + x) + b] = (byte) value;
//                }
//            }
//        }
//
//        return flatState;
//    }

}
