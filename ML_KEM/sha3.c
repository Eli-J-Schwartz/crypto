#pragma once

#include <stdint.h>
#include <stdlib.h>

#define ROT(x, n) ((x << n) | (x >> (64-n)))

int r[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};
int p[25] = {0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4};
uint64_t rc[24] = {
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008
};


void keccak(uint8_t* state) {
    uint64_t A[25] = {0};
    uint64_t B[25] = {0};
    for (int i = 0; i < 200; i++) {
        A[i>>3] ^= (uint64_t) (state[i]) << (i*8);
    }

    for (int i = 0; i < 24; i++) {
        uint64_t C[5] = {0};
        for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) C[x] ^= A[x+5*y];
        for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) A[x+5*y] ^= C[(x+4)%5] ^ ROT(C[(x+1)%5], 1);

        for (int x = 0; x < 25; x++) B[p[x]] = ROT(A[x], r[x]);

        for (int y = 0; y < 5; y++) for (int x = 0; x < 5; x++) A[x+5*y] = B[x+5*y] ^ ((~B[(x+1)%5+5*y]) & B[(x+2)%5+5*y]);

        A[0] ^= rc[i];
    }

    for (int i = 0; i < 200; i++) {
        state[i] = (A[i>>3] >> (i*8)) & 0xff;
    }
}

uint8_t* sponge(uint8_t* in, uint64_t in_len, uint64_t out_len, int rate, int start) {
    uint8_t state[200] = {0};

    int x = 0;
    for (uint64_t i = 0; i < in_len; i++) {
        if (x == rate) {
            keccak(state);
            x = 0;
        }
        state[x] ^= in[i];
        x++;
    }

    state[x] ^= start;
    state[rate-1] ^= 0x80;
    keccak(state);

    uint8_t* out = calloc(out_len, sizeof(uint8_t));
    x = 0;
    for (uint64_t i = 0; i < out_len; i++) {
        if (x == rate) {
            keccak(state);
            x = 0;
        }
        out[i] = state[x];
        x++;
    }

    return out;
}

uint8_t* SHA3_256(uint8_t* in, uint64_t in_len) {
    return sponge(in, in_len, 32, 136, 0x06);
}

uint8_t* SHA3_512(uint8_t* in, uint64_t in_len) {
    return sponge(in, in_len, 64, 72, 0x06);
}

uint8_t* SHAKE128(uint8_t* in, uint64_t in_len, uint64_t out_len) {
    return sponge(in, in_len, out_len/8, 168, 0x1F);
}

uint8_t* SHAKE256(uint8_t* in, uint64_t in_len, uint64_t out_len) {
    return sponge(in, in_len, out_len/8, 136, 0x1F);
}
