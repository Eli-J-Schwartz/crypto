public class Argon2 {
    private static final int parallelism = 4;
    private static final int tagLength = 32;
    private static final int memorySize = 32;
    private static final int iterations = 3;
    private static final int version = 0x13;
    public static final int HASHTYPE_ARGON2D = 0;
    public static final int HASHTYPE_ARGON2I = 1;
    public static final int HASHTYPE_ARGON2ID = 2;
    private static final int blockCount = (memorySize / (4*parallelism)) * (4*parallelism);
    private static final int columnCount = blockCount / parallelism;
    private static final int rowCount = parallelism;
    private static final int segmentLength = memorySize / (parallelism * 4);
    private static final int laneLength = segmentLength * 4;

    public static int[] hash(int[] password, int[] salt, int[] key, int[] data, int hashType) {
        int[] H0 = initHash(password, salt, key, data, hashType);

        //for (int i : H0) System.out.println(Integer.toHexString(i));
        //System.out.println();
        long[][] B = initBlocks(H0);

        fillMemory(B, hashType);

        return finalHash(B);
    }

    private static int[] initHash(int[] password, int[] salt, int[] key, int[] data, int hashType) {
        int[] buffer = new int[10 * 4 + password.length + salt.length + key.length + data.length];
        buffer[0] = (parallelism >>> 0) & 0xff;
        buffer[1] = (parallelism >>> 8) & 0xff;
        buffer[2] = (parallelism >>> 16) & 0xff;
        buffer[3] = (parallelism >>> 24) & 0xff;

        buffer[4] = (tagLength >>> 0) & 0xff;
        buffer[5] = (tagLength >>> 8) & 0xff;
        buffer[6] = (tagLength >>> 16) & 0xff;
        buffer[7] = (tagLength >>> 24) & 0xff;

        buffer[8] = (memorySize >>> 0) & 0xff;
        buffer[9] = (memorySize >>> 8) & 0xff;
        buffer[10] = (memorySize >>> 16) & 0xff;
        buffer[11] = (memorySize >>> 24) & 0xff;

        buffer[12] = (iterations >>> 0) & 0xff;
        buffer[13] = (iterations >>> 8) & 0xff;
        buffer[14] = (iterations >>> 16) & 0xff;
        buffer[15] = (iterations >>> 24) & 0xff;

        buffer[16] = (version >>> 0) & 0xff;
        buffer[17] = (version >>> 8) & 0xff;
        buffer[18] = (version >>> 16) & 0xff;
        buffer[19] = (version >>> 24) & 0xff;

        buffer[20] = (hashType >>> 0) & 0xff;
        buffer[21] = (hashType >>> 8) & 0xff;
        buffer[22] = (hashType >>> 16) & 0xff;
        buffer[23] = (hashType >>> 24) & 0xff;

        buffer[24] = (password.length >>> 0) & 0xff;
        buffer[25] = (password.length >>> 8) & 0xff;
        buffer[26] = (password.length >>> 16) & 0xff;
        buffer[27] = (password.length >>> 24) & 0xff;

        for (int i = 0; i < password.length; i++) buffer[28+i] = password[i];

        buffer[28+password.length] = (salt.length >>> 0) & 0xff;
        buffer[29+password.length] = (salt.length >>> 8) & 0xff;
        buffer[30+password.length] = (salt.length >>> 16) & 0xff;
        buffer[31+password.length] = (salt.length >>> 24) & 0xff;

        for (int i = 0; i < salt.length; i++) buffer[32+password.length+i] = salt[i];

        buffer[32+password.length+salt.length] = (key.length >>> 0) & 0xff;
        buffer[33+password.length+salt.length] = (key.length >>> 8) & 0xff;
        buffer[34+password.length+salt.length] = (key.length >>> 16) & 0xff;
        buffer[35+password.length+salt.length] = (key.length >>> 24) & 0xff;

        for (int i = 0; i < key.length; i++) buffer[36+password.length+salt.length+i] = key[i];

        buffer[36+password.length+salt.length+key.length] = (data.length >>> 0) & 0xff;
        buffer[37+password.length+salt.length+key.length] = (data.length >>> 8) & 0xff;
        buffer[38+password.length+salt.length+key.length] = (data.length >>> 16) & 0xff;
        buffer[39+password.length+salt.length+key.length] = (data.length >>> 24) & 0xff;

        for (int i = 0; i < data.length; i++) buffer[40+password.length+salt.length+key.length+i] = data[i];

        return Blake2b.hash(buffer, 64);
    }

    private static long[][] initBlocks(int[] H0) {
        long[][] B = new long[rowCount * columnCount][128];
        for (int lane = 0; lane < rowCount; lane++) {
            int j = lane * (memorySize / parallelism);

            int[] in = new int[H0.length + 8];
            for (int k = 0; k < H0.length; k++) in[k] = H0[k];
            in[H0.length+4] = (lane >>> 0) & 0xff;
            in[H0.length+5] = (lane >>> 8) & 0xff;
            in[H0.length+6] = (lane >>> 16) & 0xff;
            in[H0.length+7] = (lane >>> 24) & 0xff;

            in[H0.length] = 0;
            int[] temp = H(in, 1024);
            for (int i = 0; i < 1024; i++) B[j+0][i>>3] ^= (long) temp[i] << (8*(i%8));

            in[H0.length] = 1;
            temp = H(in, 1024);
            for (int i = 0; i < 1024; i++) B[j+1][i>>3] ^= (long) temp[i] << (8*(i%8));
        }
        return B;
    }

    private static void fillMemory(long[][] B, int hashType) {
        for (int pass = 0; pass < iterations; pass++) {
            //System.out.println("Pass: " + pass);
            for (int slice = 0; slice < 4; slice++) {
                for (int lane = 0; lane < parallelism; lane++) {
                    fillSegment(pass, lane, slice, B, hashType);
                }
            }
            /*for (int i = 0; i < blockCount; i++) {
                System.out.println("Block: " + i);
                for (int j = 0; j < 128; j++) {
                    System.out.println(j + ": " + Long.toHexString(B[i][j]));
                }
                System.out.println();
            }*/
        }
    }

    private static void fillSegment(int pass, int lane, int slice, long[][] B, int hashType) {
        long[] addressBlock = new long[128];
        long[] inputBlock = new long[128];
        long[] zeroBlock = new long[128];

        boolean independent = hashType == HASHTYPE_ARGON2I || (hashType == HASHTYPE_ARGON2ID && pass == 0 && slice < 2);
        int startingIndex = (pass == 0) && (slice == 0) ? 2 : 0;
        int currentOffset = lane * laneLength + slice * segmentLength + startingIndex;
        int prevOffset = (currentOffset % laneLength == 0) ? currentOffset + laneLength - 1 : currentOffset - 1;

        if (independent) {
            inputBlock[0] = pass;
            inputBlock[1] = lane;
            inputBlock[2] = slice;
            inputBlock[3] = blockCount;
            inputBlock[4] = iterations;
            inputBlock[5] = hashType;

            if (pass == 0 && slice == 0) nextAddress(zeroBlock, inputBlock, addressBlock);
        }

        for (int i = startingIndex; i < segmentLength; i++, currentOffset++, prevOffset++) {
            if (currentOffset % laneLength == 1) prevOffset = currentOffset - 1;

            long random;
            if (independent) {
                if (i % 128 == 0) nextAddress(zeroBlock, inputBlock, addressBlock);
                random = addressBlock[i % 128];
            } else {
                random = B[prevOffset][0];
            }

            int refLane = (pass == 0) && (slice == 0) ? lane : (int) ((random >>> 32) % parallelism);
            int startPos;
            int areaSize;
            if (pass == 0) {
                startPos = 0;
                if (lane == refLane) {
                    areaSize = slice * segmentLength + i - 1;
                } else {
                    areaSize = slice * segmentLength + ((i == 0) ? (-1) : 0);
                }
            } else {
                startPos = ((slice + 1) * segmentLength) % laneLength;
                if (lane == refLane) {
                    areaSize = laneLength - segmentLength + i - 1;
                } else {
                    areaSize = laneLength - segmentLength + ((i == 0) ? (-1) : 0);
                }
            }

            long posRel = random & 0xffffffffL;
            posRel = (posRel * posRel) >>> 32;
            posRel = areaSize - 1 - (areaSize * posRel >>> 32);
            int refColumn = (int) ((startPos + posRel) % laneLength);

            long[] prevBlock = B[prevOffset];
            long[] refBlock = B[(laneLength) * refLane + refColumn];

            long[] temp = G(prevBlock, refBlock);
            for (int j = 0; j < 128; j++) B[currentOffset][j] ^= temp[j];
        }
    }

    private static void nextAddress(long[] zeroBlock, long[] inputBlock, long[] addressBlock) {
        inputBlock[6]++;
        long[] temp = G(zeroBlock, inputBlock);
        for (int i = 0; i < 128; i++) addressBlock[i] = temp[i];
        temp = G(zeroBlock, addressBlock);
        for (int i = 0; i < 128; i++) addressBlock[i] = temp[i];
    }

    private static int[] finalHash(long[][] B) {
        long[] finalBlock = new long[128];

        for (int i = 0; i < parallelism; i++) {
            int lastBlockInLane = i * laneLength + (laneLength - 1);
            for (int j = 0; j < 128; j++) finalBlock[j] ^= B[lastBlockInLane][j];
        }

        int[] finalBytes = new int[1024];
        for (int i = 0; i < 1024; i++) finalBytes[i] = (int) (finalBlock[i >> 3] >>> ((i%8)*8) & 0xff);

        return H(finalBytes, tagLength);
    }

    private static int[] H(int[] message, int outLen) {
        int[] in = new int[message.length+4];
        for (int i = 0; i < message.length; i++) in[i+4] = message[i];
        in[0] = (outLen >>> 0) & 0xff;
        in[1] = (outLen >>> 8) & 0xff;
        in[2] = (outLen >>> 16) & 0xff;
        in[3] = (outLen >>> 24) & 0xff;

        if (outLen <= 64) {
            return Blake2b.hash(in, outLen);
        } else {
            int r = (outLen + 31) / 32 - 2;
            int[] out = new int[outLen];
            for (int i = 0; i < r; i++) {
                in = Blake2b.hash(in, 64);
                for (int j = 0; j < 32; j++) out[i*32+j] = in[j];
            }
            in = Blake2b.hash(in, outLen - 32*r);
            for (int i = 0; i < outLen - 32*r; i++) out[r*32+i] = in[i];
            return out;
        }
    }

    private static long[] G(long[] X, long[] Y) {
        long[] R = new long[128];
        for (int i = 0; i < 128; i++) R[i] = X[i] ^ Y[i];

        for (int i = 0; i < 8; i++) P(8*i, 8*i+1, 8*i+2, 8*i+3, 8*i+4, 8*i+5, 8*i+6, 8*i+7, R);
        for (int i = 0; i < 8; i++) P(i, i+8, i+16, i+24, i+32, i+40, i+48, i+56, R);

        long[] Z = new long[128];
        for (int i = 0; i < 128; i++) Z[i] = X[i] ^ Y[i] ^ R[i];
        return Z;
    }

    private static void P(int v0, int v2, int v4, int v6, int v8, int v10, int v12, int v14, long[] l) {
        v0 *= 2; v2 *= 2; v4 *= 2; v6 *= 2; v8 *= 2; v10 *= 2; v12 *= 2; v14 *= 2;
        int v1 = v0 + 1, v3 = v2 + 1, v5 = v4 + 1, v7 = v6 + 1, v9 = v8 + 1, v11 = v10 + 1, v13 = v12 + 1, v15 = v14 + 1;
        mix(v0, v4, v8, v12, l);
        mix(v1, v5, v9, v13, l);
        mix(v2, v6, v10, v14, l);
        mix(v3, v7, v11, v15, l);
        mix(v0, v5, v10, v15, l);
        mix(v1, v6, v11, v12, l);
        mix(v2, v7, v8, v13, l);
        mix(v3, v4, v9, v14, l);
    }

    private static void mix(int a, int b, int c, int d, long[] l) {
        l[a] += l[b] + 2 * (l[a] & 0xffffffffL) * (l[b] & 0xffffffffL);
        l[d] = rot(l[d] ^ l[a], 32);
        l[c] += l[d] + 2 * (l[c] & 0xffffffffL) * (l[d] & 0xffffffffL);
        l[b] = rot(l[b] ^ l[c], 24);
        l[a] += l[b] + 2 * (l[a] & 0xffffffffL) * (l[b] & 0xffffffffL);
        l[d] = rot(l[d] ^ l[a], 16);
        l[c] += l[d] + 2 * (l[c] & 0xffffffffL) * (l[d] & 0xffffffffL);
        l[b] = rot(l[b] ^ l[c], 63);
    }

    private static long rot(long x, long r) {
        return (x >>> r) ^ (x << (64-r));
    }
}
