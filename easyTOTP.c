#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#define uint unsigned int

int leftRotate(uint x, int n) {
    return ((x << n) ^ (x >> (32-n))) & 0xffffffffu;
}

uint* preProcess(uint* message, int length) {
    int paddedLength = ((length+8+64)/64)*64;
    uint* padded = calloc(paddedLength, sizeof(uint));
    for (int i = 0; i < length; i++) {
        padded[i] = message[i];
    }
    padded[length] = 0x80;
    for (int i = 0; i < 8; i++) {
        padded[paddedLength - i - 1] = (((long) length * 8) >> (i*8)) & 0xffu;
    }
    uint* processed = calloc(paddedLength / 4, sizeof(uint));
    for (int i = 0; i < paddedLength; i++) {
        processed[i/4] ^= padded[i] << (8 * (3-i%4));
    }
    return processed;
}

uint* generateMessageSchedule(uint* messageBlock) {
    uint* w = calloc(80, sizeof(uint));
    for (int i = 0; i < 16; i++) {
        w[i] = messageBlock[i];
    }
    for (int i = 16; i < 80; i++) {
        w[i] = leftRotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    return w;
}

void shaStep(uint* a, uint* b, uint* c, uint* d, uint* e, int w, int i) {
    uint f, k;
    if (i < 20) {
        f = (*b & *c) | ((~*b) & *d);
        k = 0x5a827999u;
    } else if (i < 40) {
        f = *b ^ *c ^ *d;
        k = 0x6ed9eba1u;
    } else if (i < 60) {
        f = (*b & *c) | (*b & *d) | (*c & *d);
        k = 0x8f1bbcdcu;
    } else {
        f = *b ^ *c ^ *d;
        k = 0xca62c1d6u;
    }

    uint temp = (leftRotate(*a, 5) + f + *e + k + w) & 0xffffffffu;
    *e = *d;
    *d = *c;
    *c = leftRotate(*b, 30);
    *b = *a;
    *a = temp;
}

uint* sha1(uint* message, int length) {
    uint* messageBlocks = preProcess(message, length);
    int blockCount = (length+8+64)/64;

    uint h0 = 0x67452301u;
    uint h1 = 0xefcdab89u;
    uint h2 = 0x98badcfeu;
    uint h3 = 0x10325476u;
    uint h4 = 0xc3d2e1f0u;

    for (int i = 0; i < blockCount; i++) {
        uint a = h0;
        uint b = h1;
        uint c = h2;
        uint d = h3;
        uint e = h4;

        uint* w = generateMessageSchedule(messageBlocks + 16 * i);
        for (int i = 0; i < 80; i++) {
            shaStep(&a, &b, &c, &d, &e, w[i], i);
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }
    uint hashValue[] = {h0, h1, h2, h3, h4};

    uint* final = calloc(20, sizeof(int));
    for (int i = 0; i < 20; i++) {
        final[i] = (hashValue[i/4] >> (8 * (3-i%4))) & 0xff;
    }
    return final;
}

uint* hmacSha1(uint* k, int kLen, uint* m, int mLen) {
    if (kLen > 64) {
        k = sha1(k, kLen);
        kLen = 20;
    }

    uint* h1 = calloc(64 + mLen, sizeof(uint));
    uint* h2 = calloc(64 + 20, sizeof(uint));
    for (int i = 0; i < kLen; i++) {
        h1[i] = k[i];
        h2[i] = k[i];
    }
    for (int i = 0; i < 64; i++) {
        h1[i] ^= 0x36;
        h2[i] ^= 0x5c;
    }

    for (int i = 0; i < mLen; i++) {
        h1[i+64] = m[i];
    }
    uint* temp = sha1(h1, 64 + mLen);
    for (int i = 0; i < 20; i++) {
        h2[i+64] = temp[i];
    }

    return sha1(h2, 64 + 20);
}

int hotp(uint* k, int kLen, unsigned long n) {
    uint* m = calloc(8, sizeof(uint));
    for (int i = 0; i < 8; i++) {
        m[i] = (n >> (8 * (7-i))) & 0xff;
    }
    uint* hmac = hmacSha1(k, kLen, m, 8);
    int index = hmac[19] & 0xf;

    return ((hmac[index] & 0x7f) << 24) ^ (hmac[index+1] << 16) ^ (hmac[index+2] << 8) ^ hmac[index+3];
}

void printHexArray(uint* array, int arrLength, int printLength, bool newLines) {
    if (newLines) {
        for (int i = 0; i < arrLength; i++) {
            printf("%0*x\n", printLength, array[i]);
        }
    } else {
        for (int i = 0; i < arrLength; i++) {
            printf("%0*x ", printLength, array[i]);
        }
        printf("\n");
    }
}

int main() {
    char key[] = "12345678901234567890";
    uint* k = calloc(strlen(key), sizeof(uint));
    for (int i = 0; i < strlen(key); i++) k[i] = key[i];
    
    for (int i = 0; i < 10; i++) {
        int out = hotp(k, strlen(key), i);
        printf("%d %06d\n", i, out%1000000);
    }

    k = calloc(20, sizeof(uint));
    int out = hotp(k, 20, time(NULL)/30);
    printf("%06d, %ld seconds left.\n", out%1000000, 30-time(NULL)%30);
}