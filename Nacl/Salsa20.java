public class Salsa20 {
    private static int rotate(int x, int r) {
        return (x << r) ^ (x >>> (32-r));
    }

    private static void quarterRound(int[] l, int a, int b, int c, int d) {
        l[b] ^= rotate(l[a] + l[d], 7);
        l[c] ^= rotate(l[b] + l[a], 9);
        l[d] ^= rotate(l[c] + l[b], 13);
        l[a] ^= rotate(l[d] + l[c], 18);
    }

    private static int[] salsa(int[] k, int[] n, boolean isHSalsa) {
        int[] l = new int[16];
        l[0] = 0x61707865;
        l[5] = 0x3320646e;
        l[10] = 0x79622d32;
        l[15] = 0x6b206574;

        for (int i = 0; i < 4; i++) {
            l[i+1] = k[i*4] ^ (k[i*4+1] << 8) ^ (k[i*4+2] << 16) ^ (k[i*4+3] << 24);
            l[i+11] = k[i*4+16] ^ (k[i*4+17] << 8) ^ (k[i*4+18] << 16) ^ (k[i*4+19] << 24);
            l[i+6] = n[i*4] ^ (n[i*4+1] << 8) ^ (n[i*4+2] << 16) ^ (n[i*4+3] << 24);
        }

        int[] t = new int[16];
        for (int i = 0; i < 16; i++) t[i] = l[i];

        for (int i = 0; i < 10; i++) {
            quarterRound(l, 0, 4, 8, 12);
            quarterRound(l, 5, 9, 13, 1);
            quarterRound(l, 10, 14, 2, 6);
            quarterRound(l, 15, 3, 7, 11);

            quarterRound(l, 0, 1, 2, 3);
            quarterRound(l, 5, 6, 7, 4);
            quarterRound(l, 10, 11, 8, 9);
            quarterRound(l, 15, 12, 13, 14);
        }

        if (isHSalsa) {
            int[] out = new int[32];
            for (int i = 0; i < 4; i++) {
                out[i*4] = l[i*5] & 0xff;
                out[i*4+1] = (l[i*5] >> 8) & 0xff;
                out[i*4+2] = (l[i*5] >> 16) & 0xff;
                out[i*4+3] = (l[i*5] >> 24) & 0xff;
                out[i*4+16] = l[i+6] & 0xff;
                out[i*4+17] = (l[i+6] >> 8) & 0xff;
                out[i*4+18] = (l[i+6] >> 16) & 0xff;
                out[i*4+19] = (l[i+6] >> 24) & 0xff;
            }
            return out;
        } else {
            for (int i = 0; i < 16; i++) l[i] += t[i];
            int[] out = new int[64];
            for (int i = 0; i < 16; i++) {
                out[i*4] = l[i] & 0xff;
                out[i*4+1] = (l[i] >> 8) & 0xff;
                out[i*4+2] = (l[i] >> 16) & 0xff;
                out[i*4+3] = (l[i] >> 24) & 0xff;
            }
            return out;
        }
    }

    public static int[] HSalsa20(int[] k, int[] n) {
        return salsa(k, n, true);
    }

    public static int[] Salsa20(int[] k, int[] n, int l) {
        int[] out = new int[l];
        int[] in = new int[16];
        for (int i = 0; i < 8; i++) in[i] = n[i];
        int[] vals = new int[64];
        for (int i = 0; i < l; i++) {
            if (i % 64 == 0) {
                in[8] = (i >> 6) & 0xff;
                in[9] = (i >> 14) & 0xff;
                in[10] = (i >> 22) & 0xff;
                in[11] = (i >> 30) & 0xff;
                vals = salsa(k, in, false);
            }
            out[i] = vals[i%64];
        }
        return out;
    }
}
