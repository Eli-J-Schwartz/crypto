#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "sha3.c"

uint64_t n = 256;
uint64_t q = 3329;

uint64_t zeta_pows[128] = {1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447,
    1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304,
    2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617,
    1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156,
    3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298,
    2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150,
    2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154};

struct mlkem_params {
    uint8_t k;
    uint8_t eta_1;
    uint8_t eta_2;
    uint8_t d_u;
    uint8_t d_v;
};

struct mlkem_params ML_KEM_512 =  {2, 3, 2, 10, 4};
struct mlkem_params ML_KEM_768 =  {3, 2, 2, 10, 4};
struct mlkem_params ML_KEM_1024 = {4, 2, 2, 11, 5};

uint8_t* PRF(uint8_t eta, uint8_t* s, uint8_t b) {
    uint8_t* tmp = calloc(33, sizeof(uint8_t));
    for (int i = 0; i < 32; i++) tmp[i] = s[i];
    tmp[32] = b;
    return SHAKE256(tmp, 33, 8*64*eta);
}

uint8_t* H(uint8_t* s, uint64_t s_len) {
    return SHA3_256(s, s_len);
}

uint8_t* J(uint8_t* s, uint64_t s_len) {
    return SHAKE256(s, s_len, 8*32);
}

uint8_t* G(uint8_t* c, uint64_t c_len) {
    return SHA3_512(c, c_len);
}

uint8_t* XOF(uint8_t* str, uint64_t str_len, uint64_t l) {
    return SHAKE128(str, str_len, 8*l);
}

uint64_t* ScalarMult(uint64_t a, uint64_t* X, uint64_t l, uint64_t m) {
    uint64_t* Z = calloc(l, sizeof(uint64_t));
    for (int i = 0; i < l; i++) Z[i] = (a * X[i]) % m;
    return Z;
}

uint64_t* VectorAdd(uint64_t* X, uint64_t* Y, uint64_t l, uint64_t m) {
    uint64_t* W = calloc(l, sizeof(uint64_t));
    for (int i = 0; i < l; i++) W[i] = (X[i] + Y[i]) % m;
    return W;
}

uint8_t* BitsToBytes(uint8_t* in, uint64_t in_len) {
    uint8_t* out = calloc(in_len>>3, sizeof(uint8_t));
    for (int i = 0; i < in_len; i++) {
        out[i>>3] += in[i] << (i&7);
    }
    return out;
}

uint8_t* BytesToBits(uint8_t* in, uint64_t in_len) {
    uint8_t* out = calloc(in_len<<3, sizeof(uint8_t));
    for (int i = 0; i < in_len<<3; i++) {
        out[i] = (in[i>>3] >> (i&7)) & 1;
    }
    return out;
}

uint64_t Compress(uint8_t d, uint64_t x) {
    return (((x << d) + 1664) / q) & ((1 << d) - 1);
}

uint64_t Decompress(uint8_t d, uint64_t x) {
    return (x * q + (1 << (d - 1))) >> d;
}

uint8_t* ByteEncode(uint8_t d, uint64_t* F) {
    uint8_t* out = calloc(256*d, sizeof(uint8_t));

    for (int i = 0; i < 256*d; i++) {
        out[i] = (F[i/d] >> (i%d)) & 1;
    }
    return BitsToBytes(out, 256*d);
}

uint64_t* ByteDecode(uint8_t d, uint8_t* B) {
    uint64_t* out = calloc(256, sizeof(uint64_t));
    uint8_t* tmp = BytesToBits(B, 256*d);
    for (int i = 0; i < 256*d; i++) {
        out[i/d] += ((uint64_t) tmp[i]) << (i%d);
    }

    return out;
}

uint64_t* SampleNTT(uint8_t* B) {
    uint64_t* a = calloc(256, sizeof(uint64_t));
    uint8_t* tmp = XOF(B, 34, 280*3);

    int j = 0;
    for (int i = 0; i < 280 && j < 256; i++) {
        uint64_t d_1 = tmp[i*3] + ((tmp[i*3+1] & 15) << 8);
        uint64_t d_2 = (tmp[i*3+1] >> 4) + (tmp[i*3+2] << 4);

        if (d_1 < q) {
            a[j] = d_1;
            j++;
        }

        if (d_2 < q && j < 256) {
            a[j] = d_2;
            j++;
        }
    }

    return a;
}

uint64_t* SamplePolyCBD(uint8_t eta, uint8_t* B) {
    uint8_t* b = BytesToBits(B, 64*eta);
    uint64_t* f = calloc(256, sizeof(uint64_t));

    for (int i = 0; i < 256; i++) {
        for (int j = 0; j < eta; j++) {
            f[i] += b[2*i*eta + j];
            f[i] -= b[2*i*eta + eta + j];
        }
        f[i] += q;
        f[i] %= q;
    }

    return f;
}

uint64_t* NTT(uint64_t* f) {
    uint64_t* f_ = calloc(256, sizeof(uint64_t));
    for (int i = 0; i < 256; i++) f_[i] = f[i];

    int i = 1;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < 256; start += 2*len) {
            uint64_t zeta = zeta_pows[i];
            i++;
            for (int j = start; j < start+len; j++) {
                uint64_t t = (zeta * f_[j+len]) % q;
                f_[j+len] = (f_[j] - t + q) % q;
                f_[j] = (f_[j] + t) % q;
            }
        }
    }

    return f_;
}

uint64_t* NTT_1(uint64_t* f_) {
    uint64_t* f = calloc(256, sizeof(uint64_t));

    for (int i = 0; i < 256; i++) f[i] = f_[i];

    int i = 127;
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < 256; start += 2*len) {
            uint64_t zeta = zeta_pows[i];
            i--;
            for (int j = start; j < start+len; j++) {
                uint64_t t = f[j];
                f[j] = (t + f[j+len]) % q;
                f[j+len] = (zeta * (f[j+len] - t + q)) % q;
            }
        }
    }

    f = ScalarMult(3303, f, 256, q);

    return f;
}

uint64_t* MultiplyNTTs(uint64_t* f, uint64_t* g) {
    uint64_t* h = calloc(256, sizeof(uint64_t));

    for (int i = 0; i < 128; i++) {
        uint64_t zeta = (i&1) ? q-zeta_pows[64+(i>>1)] : zeta_pows[64+(i>>1)];
        h[2*i] = (f[2*i] * g[2*i] + f[2*i+1] * g[2*i+1] * zeta) % q;
        h[2*i+1] = (f[2*i] * g[2*i+1] + f[2*i+1] * g[2*i]) % q;
    }

    return h;
}

uint8_t** K_PKE_KeyGen(uint8_t* d, struct mlkem_params params) {
    uint8_t* seed = calloc(33, sizeof(uint8_t));
    for (int i = 0; i < 32; i++) seed[i] = d[i];
    seed[32] = params.k;
    seed = G(seed, 33);
    uint8_t* rho = calloc(34, sizeof(uint8_t));
    for (int i = 0; i < 32; i++) rho[i] = seed[i];
    uint8_t* sigma = calloc(32, sizeof(uint8_t));
    for (int i = 0; i < 32; i++) sigma[i] = seed[i+32];
    uint8_t N = 0;

    uint64_t*** A_ = calloc(params.k, sizeof(uint64_t**));
    for (int i = 0; i < params.k; i++) {
        A_[i] = calloc(params.k, sizeof(uint64_t*));
        for (int j = 0; j < params.k; j++) {
            rho[32] = j;
            rho[33] = i;
            A_[i][j] = SampleNTT(rho);
        }
    }

    uint64_t** s = calloc(params.k, sizeof(uint64_t*));
    for (int i = 0; i < params.k; i++) {
        s[i] = SamplePolyCBD(params.eta_1, PRF(params.eta_1, sigma, N));
        N++;
    }

    uint64_t** e = calloc(params.k, sizeof(uint64_t*));
    for (int i = 0; i < params.k; i++) {
        e[i] = SamplePolyCBD(params.eta_1, PRF(params.eta_1, sigma, N));
        N++;
    }

    uint64_t** s_ = calloc(params.k ,sizeof(uint64_t*));
    for (int i = 0; i < params.k; i++) s_[i] = NTT(s[i]);

    uint64_t** e_ = calloc(params.k ,sizeof(uint64_t*));
    for (int i = 0; i < params.k; i++) e_[i] = NTT(e[i]);

    uint64_t** t_ = calloc(params.k ,sizeof(uint64_t*));
    for (int i = 0; i < params.k; i++) {
        t_[i] = calloc(256, sizeof(uint64_t));
        for (int j = 0; j < 256; j++) t_[i][j] = e_[i][j];
        for (int j = 0; j < params.k; j++) t_[i] = VectorAdd(t_[i], MultiplyNTTs(A_[i][j], s_[j]), 256, q);
    }

    uint8_t** out = calloc(2, sizeof(uint8_t*));
    out[0] = calloc(384*params.k + 32, sizeof(uint8_t));
    for (int i = 0; i < params.k; i++) {
        uint8_t* tmp = ByteEncode(12, t_[i]);
        for (int j = 0; j < 384; j++) out[0][384*i+j] = tmp[j];
    }
    for (int i = 0; i < 32; i++) out[0][384*params.k+i] = rho[i];

    out[1] = calloc(384*params.k, sizeof(uint8_t));
    for (int i = 0; i < params.k; i++) {
        uint8_t* tmp = ByteEncode(12, s_[i]);
        for (int j = 0; j < 384; j++) out[1][384*i+j] = tmp[j];
    }

    return out;
}

uint8_t* K_PKE_Encrypt(uint8_t* ek_PKE, uint8_t* m, uint8_t* r, struct mlkem_params params) {
    uint8_t N = 0;

    uint64_t** t_ = calloc(params.k, sizeof(uint64_t*));
    for (int i = 0; i < params.k; i++) t_[i] = ByteDecode(12, ek_PKE + 384*i);

    uint8_t* rho = calloc(34, sizeof(uint8_t));
    for (int i = 0; i < 32; i++) rho[i] = ek_PKE[384*params.k+i];

    uint64_t*** A_ = calloc(params.k, sizeof(uint64_t**));
    for (int i = 0; i < params.k; i++) {
        A_[i] = calloc(params.k, sizeof(uint64_t*));
        for (int j = 0; j < params.k; j++) {
            rho[32] = j;
            rho[33] = i;
            A_[i][j] = SampleNTT(rho);
        }
    }

    uint64_t** y = calloc(params.k, sizeof(uint64_t*));
    for (int i = 0; i < params.k; i++) {
        y[i] = SamplePolyCBD(params.eta_1, PRF(params.eta_1, r, N));
        N++;
    }

    uint64_t** e1 = calloc(params.k, sizeof(uint64_t*));
    for (int i = 0; i < params.k; i++) {
        e1[i] = SamplePolyCBD(params.eta_2, PRF(params.eta_2, r, N));
        N++;
    }

    uint64_t* e2 = SamplePolyCBD(params.eta_2, PRF(params.eta_2, r, N));

    uint64_t** y_ = calloc(params.k ,sizeof(uint64_t*));
    for (int i = 0; i < params.k; i++) y_[i] = NTT(y[i]);

    uint64_t** u = calloc(params.k ,sizeof(uint64_t*));
    for (int i = 0; i < params.k; i++) {
        u[i] = calloc(256, sizeof(uint64_t));
        for (int j = 0; j < params.k; j++) u[i] = VectorAdd(u[i], MultiplyNTTs(A_[j][i], y_[j]), 256, q);
        u[i] = NTT_1(u[i]);
        u[i] = VectorAdd(u[i], e1[i], 256, q);
    }

    uint64_t* mu = ByteDecode(1, m);
    for (int i = 0; i < 256; i++) mu[i] = Decompress(1, mu[i]);

    uint64_t* v = calloc(256, sizeof(uint64_t));
    for (int i = 0; i < params.k; i++) v = VectorAdd(v, MultiplyNTTs(t_[i], y_[i]), 256, q);
    v = NTT_1(v);
    v = VectorAdd(v, e2, 256, q);
    v = VectorAdd(v, mu, 256, q);

    uint8_t* c = calloc(32*(params.d_u*params.k + params.d_v), sizeof(uint8_t));
    for (int i = 0; i < params.k; i++) {
        uint64_t* tmp1 = calloc(256, sizeof(uint64_t));
        for (int j = 0; j < 256; j++) tmp1[j] = Compress(params.d_u, u[i][j]);
        uint8_t* tmp2 = ByteEncode(params.d_u, tmp1);
        for (int j = 0; j < 32*params.d_u; j++) c[i*32*params.d_u + j] = tmp2[j];
    }

    uint64_t* tmp1 = calloc(256, sizeof(uint64_t));
    for (int i = 0; i < 256; i++) tmp1[i] = Compress(params.d_v, v[i]);
    uint8_t* tmp2 = ByteEncode(params.d_v, tmp1);
    for (int i = 0; i < 32*params.d_v; i++) c[params.k*32*params.d_u + i] = tmp2[i];

    return c;
}

uint8_t* K_PKE_Decrypt(uint8_t* dk_PKE, uint8_t* c, struct mlkem_params params) {
    uint64_t** u_prime = calloc(params.k, sizeof(uint64_t*));
    for (int i = 0; i < params.k; i++) {
        u_prime[i] = ByteDecode(params.d_u, c + 32*params.d_u*i);
        for (int j = 0; j < 256; j++) u_prime[i][j] = Decompress(params.d_u, u_prime[i][j]);
    }

    uint64_t* v_prime = ByteDecode(params.d_v, c + 32*params.d_u*params.k);
    for (int i = 0; i < 256; i++) v_prime[i] = Decompress(params.d_v, v_prime[i]);

    uint64_t** s_ = calloc(params.k, sizeof(uint64_t*));
    for (int i = 0; i < params.k; i++) s_[i] = ByteDecode(12, dk_PKE + 384*i);

    uint64_t* w = v_prime;
    for (int i = 0; i < params.k; i++) {
        uint64_t* tmp = NTT_1(MultiplyNTTs(s_[i], NTT(u_prime[i])));
        w = VectorAdd(w, ScalarMult(q-1, tmp, 256, q), 256, q);
    }

    uint64_t* m = calloc(256, sizeof(uint64_t));
    for (int i = 0; i < 256; i++) m[i] = Compress(1, w[i]);

    return ByteEncode(1, m);
}

uint8_t** ML_KEM_KeyGen(uint8_t* d, uint8_t* z, struct mlkem_params params) {
    uint8_t** PKE_keys = K_PKE_KeyGen(d, params);

    uint8_t** keys = calloc(2, sizeof(uint8_t*));
    keys[0] = PKE_keys[0];
    keys[1] = calloc(768*params.k + 96, sizeof(uint8_t));
    for (int i = 0; i < 384*params.k; i++) keys[1][i] = PKE_keys[1][i];
    for (int i = 0; i < 384*params.k + 32; i++) keys[1][384*params.k + i] = PKE_keys[0][i];
    uint8_t* tmp = H(PKE_keys[0], 384*params.k + 32);
    for (int i = 0; i < 32; i++) keys[1][768*params.k + 32 + i] = tmp[i];
    for (int i = 0; i < 32; i++) keys[1][768*params.k + 64 + i] = z[i];

    return keys;
}

uint8_t** ML_KEM_Encaps(uint8_t* ek, uint8_t* m, struct mlkem_params params) {
    uint8_t* tmp1 = H(ek, params.k*384+32);
    uint8_t* tmp2 = calloc(64, sizeof(uint8_t));
    for (int i = 0; i < 32; i++) tmp2[i] = m[i];
    for (int i = 0; i < 32; i++) tmp2[i+32] = tmp1[i];
    tmp2 = G(tmp2, 64);

    uint8_t* K = calloc(32, sizeof(uint8_t));
    for (int i = 0; i < 32; i++) K[i] = tmp2[i];

    uint8_t* r = calloc(32, sizeof(uint8_t));
    for (int i = 0; i < 32; i++) r[i] = tmp2[i+32];

    uint8_t** out = calloc(2, sizeof(uint8_t*));
    out[0] = K;
    out[1] = K_PKE_Encrypt(ek, m, r, params);

    return out;
}

uint8_t* ML_KEM_Decaps(uint8_t* dk, uint8_t* c, struct mlkem_params params) {
    uint8_t* dk_PKE = dk;
    uint8_t* ek_PKE = dk + 384*params.k;
    uint8_t* h = dk + 768*params.k + 32;
    uint8_t* z = dk + 768*params.k + 64;

    uint8_t* m_prime = K_PKE_Decrypt(dk_PKE, c, params);

    uint8_t* tmp = calloc(64, sizeof(uint8_t));
    for (int i = 0; i < 32; i++) tmp[i] = m_prime[i];
    for (int i = 0; i < 32; i++) tmp[i+32] = h[i];
    tmp = G(tmp, 64);
    uint8_t* K_prime = tmp;
    uint8_t* r_prime = tmp+32;

    tmp = calloc(32*(params.d_u*params.k+params.d_v) + 32, sizeof(uint8_t));
    for (int i = 0; i < 32; i++) tmp[i] = z[i];
    for (int i = 0; i < 32*(params.d_u*params.k+params.d_v); i++) tmp[i+32] = c[i];

    uint8_t* K_bar = J(tmp, 32*(params.d_u*params.k+params.d_v) + 32);

    uint8_t* c_prime = K_PKE_Encrypt(ek_PKE, m_prime, r_prime, params);

    uint8_t test = 0;
    for (int i = 0; i < 32*(params.d_u*params.k+params.d_v); i++) test |= (c_prime[i] ^ c[i]);
    test |= test << 4;
    test |= test >> 4;
    test |= test << 2;
    test |= test >> 2;
    test |= test << 1;
    test |= test >> 1;

    for (int i = 0; i < 32; i++) K_prime[i] ^= test & (K_prime[i] ^ K_bar[i]);

    return K_prime;
}