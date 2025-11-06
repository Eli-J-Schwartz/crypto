public class X25519 {
    private static final long[] _121665 = {0xdb41,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    private static final int[] _9 = {9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    private static long[] unpack(int[] in) {
        long[] out = new long[16];
        for (int i = 0; i < 16; i++) out[i] = in[2*i] + ((long) in[2 * i + 1] << 8);
        return out;
    }

    private static void carry(long[] in) {
        long carry;
        for (int i = 0; i < 16; i++) {
            carry = in[i] >> 16;
            in[i] -= carry << 16;
            if (i < 15) in[i + 1] += carry; else in[0] += 38 * carry;
        }
    }

    private static long[] add(long[] a, long[] b) {
        long[] out = new long[16];
        for (int i = 0; i < 16; i++) out[i] = a[i] + b[i];
        return out;
    }

    private static long[] sub(long[] a, long[] b) {
        long[] out = new long[16];
        for (int i = 0; i < 16; i++) out[i] = a[i] - b[i];
        return out;
    }

    private static long[] mul(long[] a, long[] b) {
        long[] product = new long[31];
        for (int i = 0; i < 16; i++) for (int j = 0; j < 16; j++) product[i+j] += a[i] * b[j];
        for (int i = 0; i < 15; i++) product[i] += 38 * product[i + 16];
        long[] out = new long[16];
        for (int i = 0; i < 16; i++) out[i] = product[i];
        carry(out);
        carry(out);
        return out;
    }

    private static long[] inverse(long[] in) {
        long[] c = new long[16];
        for (int i = 0; i < 16; i++) c[i] = in[i];
        for (int i = 253; i >= 0; i--) {
            c = mul(c, c);
            if (i != 2 && i != 4) c = mul(c, in);
        }
        return c;
    }

    private static void swap(long[] p, long[] q, long bit) {
        long c = ~(bit - 1);
        for (int i = 0; i < 16; i++) {
            long t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static int[] pack(long[] in) {
        long[] t = new long[16];
        long[] m = new long[16];
        for (int i = 0; i < 16; i++) t[i] = in[i];
        carry(t); carry(t); carry(t);
        for (int j = 0; j < 2; j++) {
            m[0] = t[0] - 0xffed;
            for (int i = 1; i < 15; i++) {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            long carry = (m[15] >> 16) & 1;
            m[14] &= 0xffff;
            swap(t, m, 1 - carry);
        }
        int[] out = new int[32];
        for (int i = 0; i < 16; i++) {
            out[2*i] = (int) (t[i] & 0xff);
            out[2*i + 1] = (int) (t[i] >> 8);
        }
        return out;
    }

    private static int[] scalarmult(int[] scalar, int[] point) {
        int[] clamped = new int[32];
        for (int i = 0; i < 32; i++) clamped[i] = scalar[i];
        clamped[0] &= 0xf8;
        clamped[31] = (clamped[31] & 0x7f) | 0x40;
        long[] x = unpack(point);
        long[] a = new long[16];
        long[] b = new long[16];
        long[] c = new long[16];
        long[] d = new long[16];
        long[] e;
        long[] f;
        for (int i = 0; i < 16; i++) b[i] = x[i];
        a[0] = 1;
        d[0] = 1;

        for (int i = 254; i >= 0; i--) {
            long bit = (clamped[i >> 3] >> (i & 7)) & 1;
            swap(a, b, bit);
            swap(c, d, bit);
            e = add(a, c);
            a = sub(a, c);
            c = add(b, d);
            b = sub(b, d);
            d = mul(e, e);
            f = mul(a, a);
            a = mul(c, a);
            c = mul(b, e);
            e = add(a, c);
            a = sub(a, c);
            b = mul(a, a);
            c = sub(d, f);
            a = mul(c, _121665);
            a = add(a, d);
            c = mul(c, a);
            a = mul(d, f);
            d = mul(b, x);
            b = mul(e, e);
            swap(a, b, bit);
            swap(c, d, bit);
        }
        c = inverse(c);
        a = mul(a, c);
        return pack(a);
    }

    public static int[] keygen(int[] sk) {
        return scalarmult(sk, _9);
    }

    public static int[] shared(int[] pk, int[] sk) {
        return scalarmult(sk, pk);
    }
}