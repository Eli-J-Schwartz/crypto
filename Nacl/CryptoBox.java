public class CryptoBox {
    public static int[] box(int[] sk, int[] pk, int[] nonce, int[] msg) {
        int[] n1 = new int[16];
        int[] n2 = new int[8];
        for (int i = 0; i < 16; i++) n1[i] = nonce[i];
        for (int i = 0; i < 8; i++) n2[i] = nonce[i+16];

        int[] ss = X25519.shared(pk, sk);

        int[] k1 = Salsa20.HSalsa20(ss, new int[16]);
        int[] k2 = Salsa20.HSalsa20(k1, n1);
        int[] stream = Salsa20.Salsa20(k2, n2, msg.length + 32);

        int[] polykey = new int[32];
        int[] ct = new int[msg.length];
        for (int i = 0; i < 32; i++) polykey[i] = stream[i];
        for (int i = 0; i < msg.length; i++) ct[i] = msg[i] ^ stream[i + 32];

        int[] tag = Poly1305.sign(ct, polykey);

        int[] out = new int[msg.length + 16];
        for (int i = 0; i < 16; i++) out[i] = tag[i];
        for (int i = 0; i < msg.length; i++) out[i+16] = ct[i];

        return out;
    }

    public static int[] unbox(int[] sk, int[] pk, int[] nonce, int[] data) {
        int[] n1 = new int[16];
        int[] n2 = new int[8];
        for (int i = 0; i < 16; i++) n1[i] = nonce[i];
        for (int i = 0; i < 8; i++) n2[i] = nonce[i+16];

        int[] ss = X25519.shared(pk, sk);

        int[] k1 = Salsa20.HSalsa20(ss, new int[16]);
        int[] k2 = Salsa20.HSalsa20(k1, n1);
        int[] stream = Salsa20.Salsa20(k2, n2, data.length + 16);

        int[] polykey = new int[32];
        int[] msg = new int[data.length - 16];
        for (int i = 0; i < 32; i++) polykey[i] = stream[i];
        for (int i = 0; i < msg.length; i++) msg[i] = data[i+16] ^ stream[i + 32];
        int[] ct = new int[data.length - 16];
        for (int i = 0; i < ct.length; i++) ct[i] = data[i+16];

        int[] tag = Poly1305.sign(ct, polykey);
        int valid = 0;
        for (int i = 0; i < 16; i++) valid |= tag[i] ^ data[i];

        return valid == 0 ? msg : null;
    }
}
