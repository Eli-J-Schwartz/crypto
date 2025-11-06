#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#define ROT(x, n) ((x << n) | (x >> (64-n)))
#define FOR(i, n) for (i = 0; i < n; i++)
#define ulong unsigned long

ulong rotations[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};
ulong permutation[25] = {0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4};
ulong roundConstants[24] = {
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

void keccak(int* state) {
	int x, y, t, round;
	ulong A[25], B[25], C[5];
	for (int i = 0; i < 25; i++) A[i] = 0;
	for (int i = 0; i < 200; i++) A[i/8] ^= ((ulong) state[i]) << (i%8*8);

	FOR(round, 24) {
		// Theta
		FOR(x, 5) {
			C[x] = 0;
			FOR(y, 5) C[x] ^= A[y*5+x];
		}
		FOR (x, 5) {
			t = C[(x+4)%5] ^ ROT(C[(x+1)%5], 1);
			FOR (y, 5) A[y*5+x] ^= C[(x+4)%5] ^ ROT(C[(x+1)%5], 1);
		}
	
		// Rho & Pi
		FOR (t, 25) {
			B[permutation[t]] = ROT(A[t], rotations[t]);
		}

		// Chi
		FOR (x, 5) FOR(y, 5) {
			A[5*y+x] = B[5*y+x] ^ (~B[5*y+(x+1)%5] & B[5*y+(x+2)%5]);
		}

		// Iota
		A[0] ^= roundConstants[round];
	}

	for (int i = 0; i < 200; i++) state[i] = (int) ((A[i/8] >> (i%8*8)) & 0xff);
}

int* shake256(int* input, int inputLen, int outputLen) {
	//for (int i = 0; i < inputLen; i++) printf("%02x", input[i]); printf("\n"); 

	int* state = calloc(200, sizeof(int));
	int i;
	for (i = 0; i < inputLen; i++) {
		state[i%136] ^= input[i];
		if (i%136 == 135) keccak(state);
	}
	state[i%136] ^= 0x1f;
	state[135] ^= 0x80;
	keccak(state);

	int* output = calloc(outputLen, sizeof(int));
	for (i = 0; i < outputLen; i++) {
		output[i] = state[i%136];
		if (i%136 == 135) keccak(state);
	}

	free(state);

	return output;
}

void test() {
	//int* state = calloc(200, sizeof(int));
	//state[0] = 31;
	//state[135] = 128;
	//keccak(state);
	//for (int i = 0; i < 200; i++) printf("%02X\n", state[i]);

	/*int* in = calloc(272, sizeof(int));
	for (int i = 0; i < 272; i++) in[i] = 0xA3;
	int* vals = shake256(in, 1, 513);
	for (int i = 0; i < 513; i++) {
		printf("%02X ", vals[i]);
		if (i%16 == 15) printf("\n");
	}
	printf("\n");*/

	bool allValid = true;

	FILE* fptr = fopen("/Users/elischwartz/Downloads/shakebytetestvectors/SHAKE256ShortMsg.rsp", "r");
	char str[1000];
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	
	while (fgets(str, 1000, fptr)) {
		int len;
		fscanf(fptr, "Len = %d\n", &len);
		len /= 8;
		printf("%d: ", len);

		fread(str, sizeof(char), 6, fptr);
		int input[len];
		for (int i = 0; i < len; i++) {
			int temp;
			fscanf(fptr, "%02x", &temp);
			input[i] = temp;
		}

		int* output = shake256(input, len, 32);
		for (int i = 0; i < 32; i++)printf("%02x", output[i]);

		fgets(str, 1000, fptr);
		fread(str, sizeof(char), 9, fptr);
		bool valid = true;
		for (int i = 0; i < 32; i++) {
			int temp;
			fscanf(fptr, "%02x", &temp);
			if (temp != output[i]) {valid = false; allValid = false;}
		}

		printf(valid?" PASS\n":" FAIL\n");

		fgets(str, 1000, fptr);
	}

	fptr = fopen("/Users/elischwartz/Downloads/shakebytetestvectors/SHAKE256LongMsg.rsp", "r");
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	
	while (fgets(str, 1000, fptr)) {
		int len;
		fscanf(fptr, "Len = %d\n", &len);
		len /= 8;
		printf("%d: ", len);

		fread(str, sizeof(char), 6, fptr);
		int input[len];
		for (int i = 0; i < len; i++) {
			int temp;
			fscanf(fptr, "%02x", &temp);
			input[i] = temp;
		}

		int* output = shake256(input, len, 32);
		for (int i = 0; i < 32; i++)printf("%02x", output[i]);

		fgets(str, 1000, fptr);
		fread(str, sizeof(char), 9, fptr);
		bool valid = true;
		for (int i = 0; i < 32; i++) {
			int temp;
			fscanf(fptr, "%02x", &temp);
			if (temp != output[i]) {valid = false; allValid = false;}
		}

		printf(valid?" PASS\n":" FAIL\n");

		fgets(str, 1000, fptr);
	}

	fptr = fopen("/Users/elischwartz/Downloads/shakebytetestvectors/SHAKE256VariableOut.rsp", "r");
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	fgets(str, 1000, fptr);
	
	while (fgets(str, 1000, fptr)) {
		int len;
		fscanf(fptr, "Outputlen = %d\n", &len);
		len /= 8;
		printf("%d: ", len);

		fread(str, sizeof(char), 6, fptr);
		int input[32];
		for (int i = 0; i < 32; i++) {
			int temp;
			fscanf(fptr, "%02x", &temp);
			input[i] = temp;
		}

		int* output = shake256(input, 32, len);
		for (int i = 0; i < len; i++)printf("%02x", output[i]);

		fgets(str, 1000, fptr);
		fread(str, sizeof(char), 9, fptr);
		bool valid = true;
		for (int i = 0; i < len; i++) {
			int temp;
			fscanf(fptr, "%02x", &temp);
			if (temp != output[i]) {valid = false; allValid = false;}
		}

		printf(valid?" PASS\n":" FAIL\n");

		fgets(str, 1000, fptr);
		fgets(str, 1000, fptr);
	}

	if (allValid) printf("ALL TESTS PASS\n");
}

/*int main() {
	test();
}*/