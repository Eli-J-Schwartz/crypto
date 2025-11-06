public class Poly1305 {
    private static final int[] _MINUSP = {5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252};

    private static int[] add(int[] h, int[] c) {
        int[] out = new int[17];
        int carry = 0;
        for (int i = 0; i < 17; i++) {
            carry += h[i] + c[i];
            out[i] = carry & 0xff;
            carry >>= 8;
        }
        return out;
    }

    private static void carry(int[] h) {
        int carry = 0;
        for (int i = 0; i < 16; i++) {
            carry += h[i];
            h[i] = carry & 0xff;
            carry >>= 8;
        }
        carry += h[16];
        h[16] = carry & 3;
        carry = 5 * (carry >> 2);
        for (int i = 0; i < 16; i++) {
            carry += h[i];
            h[i] = carry & 0xff;
            carry >>= 8;
        }
        carry += h[16];
        h[16] = carry;
    }

    private static int[] mul(int[] h, int[] r) {
        int[] product = new int[17];
        for (int i = 0; i < 17; i++) {
            int sum = 0;
            for (int j = 0; j <= i; j++) sum += h[j] * r[i-j];
            for (int j = i+1; j < 17; j++) sum += 320 * h[j] * r[i+17-j];
            product[i] = sum;
        }
        carry(product);
        return product;
    }

    private static void freeze(int[] h) {
        int[] t = new int[17];
        for (int i = 0; i < 17; i++) t[i] = h[i];
        h = add(h, _MINUSP);
        int negative = -(h[16] >> 7);
        for (int i = 0; i < 17; i++) h[i] ^= negative & (h[i] ^ t[i]);
    }

    public static int[] sign(int[] m, int[] k) {
        int[] r = new int[17];
        int[] h = new int[17];
        for (int i = 0; i < 16; i++) r[i] = k[i];
        r[3] &= 15;
        r[7] &= 15;
        r[11] &= 15;
        r[15] &= 15;
        r[4] &= 252;
        r[8] &= 252;
        r[12] &= 252;

        for (int i = 0; i < m.length; i+=16) {
            int[] c = new int[17];
            int j;
            for (j = 0; j < 16 && i + j < m.length; j++) c[j] = m[i + j];
            c[j] = 1;
            h = add(h, c);
            h = mul(h, r);
        }

        freeze(h);
        int[] c = new int[17];
        for (int i = 0; i < 16; i++) c[i] = k[i+16];
        h = add(h, c);
        int[] out = new int[16];
        for (int i = 0; i < 16; i++) out[i] = h[i];
        return out;
    }

    public static boolean verify(int[] m, int[] k, int[] s) {
        int[] t = sign(m, k);
        boolean valid = true;
        for (int i = 0; i < 16; i++) valid &= s[i] == t[i];
        return valid;
    }
}
