#include "shake.c"
#include <stdbool.h>
#define ulong unsigned long

#define WOTS_HASH 0
#define WOTS_PK 1
#define TREE 2
#define FORS_TREE 3
#define FORS_ROOTS 4
#define WOTS_PRF 5
#define FORS_PRF 6

struct parameters {
	int n;
	int h;
	int d;
	int h_prime;
	int a;
	int k;
	int m;
	char* s;
};

const struct parameters params128s = {16, 63,  7, 9, 12, 14, 30, "128s"};
const struct parameters params128f = {16, 66, 22, 3,  6, 33, 34, "128f"};
const struct parameters params192s = {24, 63,  7, 9, 14, 17, 39, "192s"};
const struct parameters params192f = {24, 66, 22, 3,  8, 33, 42, "192f"};
const struct parameters params256s = {32, 64,  8, 8, 14, 22, 47, "256s"};
const struct parameters params256f = {32, 68, 17, 4,  9, 35, 49, "256f"};

struct parameters params[6] = {params128s, params128f, params192s, params192f, params256s, params256f};
	
int* PRF_msg(struct parameters params, int* SK_prf, int* opt_rand, int* M, int M_len) {
	int n = params.n;

	int input[2*n+M_len];
	for (int i = 0; i < n; i++) input[i] = SK_prf[i];
	for (int i = 0; i < n; i++) input[n+i] = opt_rand[i];
	for (int i = 0; i < M_len; i++) input[2*n+i] = M[i];

	int* output = shake256(input, 2*n+M_len, n);

	return output;
}

int* H_msg(struct parameters params, int* R, int* PK_seed, int* PK_root, int* M, int M_len) {
	int n = params.n;
	int input[3*n+M_len];
	for (int i = 0; i < n; i++) input[i] = R[i];
	for (int i = 0; i < n; i++) input[n+i] = PK_seed[i];
	for (int i = 0; i < n; i++) input[2*n+i] = PK_root[i];
	for (int i = 0; i < M_len; i++) input[3*n+i] = M[i];

	int* output = shake256(input, 3*n+M_len, params.m);

	return output;
}

int* PRF(struct parameters params, int* PK_seed, int* SK_seed, int* ADRS) {
	int n = params.n;

	int input[2*n+32];
	for (int i = 0; i < n; i++) input[i] = PK_seed[i];
	for (int i = 0; i < 32; i++) input[n+i] = ADRS[i];
	for (int i = 0; i < n; i++) input[n+32+i] = SK_seed[i];

	int* output = shake256(input, 2*n+32, n);

	return output;
}

int* F(struct parameters params, int* PK_seed, int* ADRS, int* M_1) {
	int n = params.n;

	int input[2*n+32];
	for (int i = 0; i < n; i++) input[i] = PK_seed[i];
	for (int i = 0; i < 32; i++) input[n+i] = ADRS[i];
	for (int i = 0; i < n; i++) input[n+32+i] = M_1[i];

	int* output = shake256(input, 2*n+32, n);

	return output;
}

int* H(struct parameters params, int* PK_seed, int* ADRS, int* M_2) {
	int n = params.n;

	int input[3*n+32];
	for (int i = 0; i < n; i++) input[i] = PK_seed[i];
	for (int i = 0; i < 32; i++) input[n+i] = ADRS[i];
	for (int i = 0; i < 2*n; i++) input[n+32+i] = M_2[i];

	int* output = shake256(input, 3*n+32, n);

	return output;
}

int* T_l(struct parameters params, int* PK_seed, int* ADRS, int* M_l, int l) {
	int n = params.n;

	int input[(1+l)*n+32];
	for (int i = 0; i < n; i++) input[i] = PK_seed[i];
	for (int i = 0; i < 32; i++) input[n+i] = ADRS[i];
	for (int i = 0; i < l*n; i++) input[n+32+i] = M_l[i];

	int* output = shake256(input, (1+l)*n+32, n);

	return output;
}

void setLayerAddress(int* ADRS, ulong l) {
	for (int i = 0; i < 4; i++) {
		ADRS[i] = (l >> (8*(3-i))) & 0xff;
	}
}

void setTreeAddress(int* ADRS, ulong t) {
	for (int i = 0; i < 8; i++) {
		ADRS[i+8] = (t >> (8*(7-i))) & 0xff;
	}
}

void setTypeAndClear(int* ADRS, ulong Y) {
	for (int i = 0; i < 4; i++) {
		ADRS[i+16] = (Y >> (8*(3-i))) & 0xff;
	}
	for (int i = 0; i < 12; i++) {
		ADRS[i+20] = 0;
	}
}

void setKeyPairAddress(int* ADRS, ulong I) {
	for (int i = 0; i < 4; i++) {
		ADRS[i+20] = (I >> (8*(3-i))) & 0xff;
	}
}

void setChainAddress(int* ADRS, ulong I) {
	for (int i = 0; i < 4; i++) {
		ADRS[i+24] = (I >> (8*(3-i))) & 0xff;
	}
}

void setTreeHeight(int* ADRS, ulong I) {
	for (int i = 0; i < 4; i++) {
		ADRS[i+24] = (I >> (8*(3-i))) & 0xff;
	}
}

void setHashAddress(int* ADRS, ulong I) {
	for (int i = 0; i < 4; i++) {
		ADRS[i+28] = (I >> (8*(3-i))) & 0xff;
	}
}

void setTreeIndex(int* ADRS, ulong I) {
	for (int i = 0; i < 4; i++) {
		ADRS[i+28] = (I >> (8*(3-i))) & 0xff;
	}
}

ulong getKeyPairAddress(int* ADRS) {
	ulong out = 0;
	for (int i = 0; i < 4; i++) {
		out |= ADRS[i+20] << (8*(3-i));
	}
	return out;
}

ulong getTreeIndex(int* ADRS) {
	ulong out = 0;
	for (int i = 0; i < 4; i++) {
		out |= ADRS[i+28] << (8*(3-i));
	}
	return out;
}

int* base_2b(int* X, int b, int outLen) {
	int in = 0;
	int bits = 0;
	int total = 0;
	int* baseb = calloc(outLen, sizeof(int));
	
	for (int out = 0; out < outLen; out++) {
		while (bits < b) {
			total = (total << 8) + X[in];
			in++;
			bits += 8;
		}
		bits -= b;
		baseb[out] = (total >> bits) & ((1 << b) - 1);
	}

	return baseb;
}

int* chain(struct parameters params, int* X, int i, int s, int* PK_seed, int* ADRS) {
	int* temp1 = X;
	for (int j = i; j < i + s; j++) {
		setHashAddress(ADRS, j);
		int* temp2 = F(params, PK_seed, ADRS, temp1);

		if (j > i) free(temp1);
		temp1 = temp2;
	}
	return temp1;
}

int* wots_pkGen(struct parameters params, int* SK_seed, int* PK_seed, int* ADRS) {
	int len = 2*params.n + 3;
	
	int* skADRS = calloc(32, sizeof(int));
	for (int i = 0; i < 32; i++) skADRS[i] = ADRS[i];
	setTypeAndClear(skADRS, WOTS_PRF);
	setKeyPairAddress(skADRS, getKeyPairAddress(ADRS));

	int* temp1 = calloc(len * params.n, sizeof(int));

	for (int i = 0; i < len; i++) {
		setChainAddress(skADRS, i);
		int* sk = PRF(params, PK_seed, SK_seed, skADRS);
		setChainAddress(ADRS, i);
		int* temp2 = chain(params, sk, 0, 15, PK_seed, ADRS);
		for (int j = 0; j < params.n; j++) temp1[i*params.n + j] = temp2[j];

		free(temp2);
		free(sk);
	}

	int* wotspkADRS = calloc(32, sizeof(int));
	for (int i = 0; i < 32; i++) wotspkADRS[i] = ADRS[i];
	setTypeAndClear(wotspkADRS, WOTS_PK);
	setKeyPairAddress(wotspkADRS, getKeyPairAddress(ADRS));
	int* pk = T_l(params, PK_seed, wotspkADRS, temp1, len);

	free(skADRS);
	free(temp1);
	free(wotspkADRS);

	return pk;
}

int* wots_sign(struct parameters params, int* M, int* SK_seed, int* PK_seed, int* ADRS) {
	int len = 2*params.n + 3;

	int csum = 0;
	int* temp = base_2b(M, 4, 2*params.n);
	int* msg = calloc(len, sizeof(int));

	for (int i = 0; i < 2*params.n; i++) {
		csum += 15 - temp[i];
		msg[i] = temp[i];
	}
	msg[2*params.n+0] = (csum >> 8) & 0xf;
	msg[2*params.n+1] = (csum >> 4) & 0xf;
	msg[2*params.n+2] = (csum >> 0) & 0xf;

	free(temp);

	int* skADRS = calloc(32, sizeof(int));
	for (int i = 0; i < 32; i++) skADRS[i] = ADRS[i];
	setTypeAndClear(skADRS, WOTS_PRF);
	setKeyPairAddress(skADRS, getKeyPairAddress(ADRS));

	int* sig = calloc(len * params.n, sizeof(int));
	for (int i = 0; i < len; i++) {
		setChainAddress(skADRS, i);
		int* sk = PRF(params, PK_seed, SK_seed, skADRS);
		setChainAddress(ADRS, i);
		temp = chain(params, sk, 0, msg[i], PK_seed, ADRS);
		for (int j = 0; j < params.n; j++) sig[i*params.n + j] = temp[j];

		free(sk);
		if (msg[i] > 0) free(temp);
	}

	free(skADRS);
	free(msg);

	return sig;
}

int* wots_pkFromSig(struct parameters params, int* sig, int* M, int* PK_seed, int* ADRS) {
	int len = 2*params.n + 3;

	int csum = 0;
	int* temp1 = base_2b(M, 4, 2*params.n);
	int* msg = calloc(len, sizeof(int));

	for (int i = 0; i < 2*params.n; i++) {
		csum += 15 - temp1[i];
		msg[i] = temp1[i];
	}
	msg[2*params.n+0] = (csum >> 8) & 0xf;
	msg[2*params.n+1] = (csum >> 4) & 0xf;
	msg[2*params.n+2] = (csum >> 0) & 0xf;

	free(temp1);

	temp1 = calloc(len * params.n, sizeof(int));

	for (int i = 0; i < len; i++) {
		setChainAddress(ADRS, i);
		int* temp2 = chain(params, sig + params.n * i, msg[i], 15 - msg[i], PK_seed, ADRS);
		for (int j = 0; j < params.n; j++) temp1[i*params.n + j] = temp2[j];

		if (msg[i] < 15) free(temp2);
	}

	int* wotspkADRS = calloc(32, sizeof(int));
	for (int i = 0; i < 32; i++) wotspkADRS[i] = ADRS[i];
	setTypeAndClear(wotspkADRS, WOTS_PK);
	setKeyPairAddress(wotspkADRS, getKeyPairAddress(ADRS));
	int* pk = T_l(params, PK_seed, wotspkADRS, temp1, len);

	free(wotspkADRS);
	free(temp1);

	return pk;
}

int* xmss_node(struct parameters params, int* SK_seed, int i, int z, int* PK_seed, int* ADRS) {
	int* node;
	if (z == 0) {
		setTypeAndClear(ADRS, WOTS_HASH);
		setKeyPairAddress(ADRS, i);
		node = wots_pkGen(params, SK_seed, PK_seed, ADRS);
	} else {
		int* lnode = xmss_node(params, SK_seed, 2*i, z-1, PK_seed, ADRS);
		int* rnode = xmss_node(params, SK_seed, 2*i+1, z-1, PK_seed, ADRS);
		int* temp = calloc(2 * params.n, sizeof(int));
		for (int j = 0; j < params.n; j++) {
			temp[j] = lnode[j];
			temp[j+params.n] = rnode[j];
		}

		free(lnode);
		free(rnode);

		setTypeAndClear(ADRS, TREE);
		setTreeHeight(ADRS, z);
		setTreeIndex(ADRS, i);
		
		node = H(params, PK_seed, ADRS, temp);

		free(temp);
	}

	return node;
}

int* xmss_sign(struct parameters params, int* M, int* SK_seed, int idx, int* PK_seed, int* ADRS) {
	int len = 2*params.n + 3;
	int* sig_xmss = calloc((params.h_prime + len) * params.n, sizeof(int));

	for (int j = 0; j < params.h_prime; j++) {
		int k = (idx >> j) ^ 1;
		int* AUTH = xmss_node(params, SK_seed, k, j, PK_seed, ADRS);
		for (int i = 0; i < params.n; i++) sig_xmss[(len + j) * params.n + i] = AUTH[i];

		free(AUTH);
	}

	setTypeAndClear(ADRS, WOTS_HASH);
	setKeyPairAddress(ADRS, idx);
	int* sig = wots_sign(params, M, SK_seed, PK_seed, ADRS);
	for (int i = 0; i < len * params.n; i++) sig_xmss[i] = sig[i];

	free(sig);

	return sig_xmss;
}

int* xmss_pkFromSig(struct parameters params, int idx, int* sig_xmss, int* M, int* PK_seed, int* ADRS) {
	int len = 2*params.n + 3;

	setTypeAndClear(ADRS, WOTS_HASH);
	setKeyPairAddress(ADRS, idx);

	int* sig = sig_xmss;
	int* AUTH = sig_xmss + len * params.n;

	int* node = wots_pkFromSig(params, sig, M, PK_seed, ADRS);
	
	setTypeAndClear(ADRS, TREE);
	setTreeIndex(ADRS, idx);

	for (int k = 0; k < params.h_prime; k++) {
		setTreeHeight(ADRS, k+1);
		int* pair = calloc(2 * params.n, sizeof(int));
		if (((idx >> k) & 1) == 0) {
			setTreeIndex(ADRS, getTreeIndex(ADRS)/2);
			for (int i = 0; i < params.n; i++) {
				pair[i] = node[i];
				pair[i+params.n] = AUTH[k*params.n+i];
			}
		} else {
			setTreeIndex(ADRS, (getTreeIndex(ADRS)-1)/2);
			for (int i = 0; i < params.n; i++) {
				pair[i] = AUTH[k*params.n+i];
				pair[i+params.n] = node[i];
			}
		}
		free(node);

		node = H(params, PK_seed, ADRS, pair);

		free(pair);
	}

	return node;
}

int* ht_sign(struct parameters params, int* M, int* SK_seed, int* PK_seed, ulong idx_tree, int idx_leaf) {
	int len = 2*params.n + 3;
	int xmssSigLen = (params.h_prime + len) * params.n;

	int* ADRS = calloc(32, sizeof(int));
	setTreeAddress(ADRS, idx_tree);
	int* sig_ht = calloc(xmssSigLen * params.d, sizeof(int));
	
	int* sig_tmp = xmss_sign(params, M, SK_seed, idx_leaf, PK_seed, ADRS);
	for (int i = 0; i < xmssSigLen; i++) sig_ht[i] = sig_tmp[i];
	int* root = xmss_pkFromSig(params, idx_leaf, sig_tmp, M, PK_seed, ADRS);

	free(sig_tmp);

	for (int j = 1; j < params.d; j++) {
		idx_leaf = idx_tree & ((1 << params.h_prime) - 1);
		idx_tree >>= params.h_prime;
		setLayerAddress(ADRS, j);
		setTreeAddress(ADRS, idx_tree);
		sig_tmp = xmss_sign(params, root, SK_seed, idx_leaf, PK_seed, ADRS);
		for (int i = 0; i < xmssSigLen; i++) sig_ht[xmssSigLen * j + i] = sig_tmp[i];
		if (j < (params.d - 1)) {
			int* temp = xmss_pkFromSig(params, idx_leaf, sig_tmp, root, PK_seed, ADRS);
			free(root);
			root = temp;
		}

		free(sig_tmp);
	}

	free(root);
	free(ADRS);

	return sig_ht;
}

bool ht_verify(struct parameters params, int* M, int* sig_ht, int* PK_seed, ulong idx_tree, int idx_leaf, int* PK_root) {
	int len = 2*params.n + 3;
	int xmssSigLen = (params.h_prime + len) * params.n;

	int* ADRS = calloc(32, sizeof(int));
	setTreeAddress(ADRS, idx_tree);
	int* sig_tmp = sig_ht;
	int* node = xmss_pkFromSig(params, idx_leaf, sig_tmp, M, PK_seed, ADRS);

	for (int j = 1; j < params.d; j++) {
		idx_leaf = idx_tree & ((1 << params.h_prime) - 1);
		idx_tree >>= params.h_prime;
		setLayerAddress(ADRS, j);
		setTreeAddress(ADRS, idx_tree);
		sig_tmp = sig_ht + xmssSigLen * j;
		int* temp = xmss_pkFromSig(params, idx_leaf, sig_tmp, node, PK_seed, ADRS);
		free(node);
		node = temp;
	}

	free(ADRS);

	bool matches = true;
	for (int i = 0; i < params.n; i++) matches &= node[i] == PK_root[i];

	free(node);

	return matches;
}

int* fors_skGen(struct parameters params, int* SK_seed, int* PK_seed, int* ADRS, int idx) {
	int* skADRS = calloc(32, sizeof(int));
	for (int i = 0; i < 32; i++) skADRS[i] = ADRS[i];

	setTypeAndClear(skADRS, FORS_PRF);
	setKeyPairAddress(skADRS, getKeyPairAddress(ADRS));
	setTreeIndex(skADRS, idx);

	int* out = PRF(params, PK_seed, SK_seed, skADRS);
	free(skADRS);
	return out;
}

int* fors_node(struct parameters params, int* SK_seed, int i, int z, int* PK_seed, int* ADRS) {
	int* node;
	if (z == 0) {
		int* sk = fors_skGen(params, SK_seed, PK_seed, ADRS, i);
		setTreeHeight(ADRS, 0);
		setTreeIndex(ADRS, i);
		node = F(params, PK_seed, ADRS, sk);
		free(sk);
	} else {
		int* lnode = fors_node(params, SK_seed, 2*i, z-1, PK_seed, ADRS);
		int* rnode = fors_node(params, SK_seed, 2*i+1, z-1, PK_seed, ADRS);
		int* temp = calloc(2 * params.n, sizeof(int));
		for (int j = 0; j < params.n; j++) {
			temp[j] = lnode[j];
			temp[j+params.n] = rnode[j];
		}

		free(lnode);
		free(rnode);

		setTreeHeight(ADRS, z);
		setTreeIndex(ADRS, i);
		
		node = H(params, PK_seed, ADRS, temp);

		free(temp);
	}

	return node;
}

int* fors_sign(struct parameters params, int* md, int* SK_seed, int* PK_seed, int* ADRS) {
	int treeSigSize = (params.a + 1) * params.n;

	int* sig_fors = calloc(treeSigSize * params.k, sizeof(int));

	int* indices = base_2b(md, params.a, params.k);

	for (int i = 0; i < params.k; i++) {
		int* sig_tmp = fors_skGen(params, SK_seed, PK_seed, ADRS, (i << params.a) + indices[i]);
		for (int j = 0; j < params.n; j++) sig_fors[i * treeSigSize + j] = sig_tmp[j];
		for (int j = 0; j < params.a; j++) {
			int s = (indices[i] >> j) ^ 1;
			int* AUTH = fors_node(params, SK_seed, (i << (params.a - j)) + s, j, PK_seed, ADRS);
			for (int k = 0; k < params.n; k++) sig_fors[i * treeSigSize + (j + 1) * params.n + k] = AUTH[k];
			free(AUTH);
		}
		free(sig_tmp);
	}

	free(indices);

	return sig_fors;
}

int* fors_pkFromSig(struct parameters params, int* sig_fors, int* md, int* PK_seed, int* ADRS) {
	int treeSigSize = (params.a + 1) * params.n;

	int* indices = base_2b(md, params.a, params.k);
	int* root = calloc(params.n * params.k, sizeof(int));

	for (int i = 0; i < params.k; i++) {
		int* sk = sig_fors + i * treeSigSize;
		
		setTreeHeight(ADRS, 0);
		setTreeIndex(ADRS, (i << params.a) + indices[i]);
		int* node = F(params, PK_seed, ADRS, sk);
		int* auth = sig_fors + i * treeSigSize + params.n;

		for (int j = 0; j < params.a; j++) {
			setTreeHeight(ADRS, j+1);
			int* pair = calloc(2 * params.n, sizeof(int));
			if (((indices[i] >> j) & 1) == 0) {
				setTreeIndex(ADRS, getTreeIndex(ADRS)/2);
				for (int i = 0; i < params.n; i++) {
					pair[i] = node[i];
					pair[i+params.n] = auth[j*params.n+i];
				}
			} else {
				setTreeIndex(ADRS, (getTreeIndex(ADRS)-1)/2);
				for (int i = 0; i < params.n; i++) {
					pair[i] = auth[j*params.n+i];
					pair[i+params.n] = node[i];
				}
			}
			free(node);
			node = H(params, PK_seed, ADRS, pair);
			free(pair);
		}

		for (int j = 0; j < params.n; j++) root[i * params.n + j] = node[j];

		free(node);
	}

	int* forspkADRS = calloc(32, sizeof(int));
	for (int i = 0; i < 32; i++) forspkADRS[i] = ADRS[i];
	setTypeAndClear(forspkADRS, FORS_ROOTS);
	setKeyPairAddress(forspkADRS, getKeyPairAddress(ADRS));
	
	int* out = T_l(params, PK_seed, forspkADRS, root, params.k);

	free(indices);
	free(forspkADRS);
	free(root);

	return out;
}

int* slh_keygen_internal(struct parameters params, int* SK_seed, int* SK_prf, int* PK_seed) {
	int* ADRS = calloc(32, sizeof(int));
	setLayerAddress(ADRS, params.d - 1);
	int* PK_root = xmss_node(params, SK_seed, 0, params.h_prime, PK_seed, ADRS);

	int* sk = calloc(params.n * 4, sizeof(int));
	for (int i = 0; i < params.n; i++) {
		sk[i+0*params.n] = SK_seed[i];
		sk[i+1*params.n] = SK_prf[i];
		sk[i+2*params.n] = PK_seed[i];
		sk[i+3*params.n] = PK_root[i];
	}

	free(ADRS);
	free(PK_root);

	return sk;
}

int* slh_sign_internal(struct parameters params, int* M, int M_len, int* SK, int* addrnd, bool deterministic) {
	int* SK_seed = SK + params.n * 0;
	int* SK_prf = SK + params.n * 1;
	int* PK_seed = SK + params.n * 2;
	int* PK_root = SK + params.n * 3;

	int len = 2*params.n + 3;
	int xmssSigLen = (params.h_prime + len) * params.n;
	int treeSigSize = (params.a + 1) * params.n;
	
	int* SIG = calloc(params.n + treeSigSize * params.k + xmssSigLen * params.d, sizeof(int));

	int* ADRS = calloc(32, sizeof(int));
	int* opt_rand = deterministic ? addrnd : PK_seed;
	int* R = PRF_msg(params, SK_prf, opt_rand, M, M_len);
	for (int i = 0; i < params.n; i++) SIG[i] = R[i];

	int* digest = H_msg(params, R, PK_seed, PK_root, M, M_len);
	int* md = digest;
	int* tmp_idx_tree = digest + (params.k * params.a + 7) / 8;
	int* tmp_idx_leaf = tmp_idx_tree + (params.h - params.h / params.d + 7) / 8;

	ulong idx_tree = 0;
	for (int i = 0; i < (params.h - params.h / params.d + 7) / 8; i++) {
		idx_tree *= 256;
		idx_tree += tmp_idx_tree[i];
	}
	if ((params.h - params.h / params.d) != 64) {
		idx_tree &= (((ulong) 1) << (params.h - params.h / params.d)) - 1;
	}

	int idx_leaf = 0;
	for (int i = 0; i < (params.h / params.d + 7) / 8; i++) {
		idx_leaf *= 256;
		idx_leaf += tmp_idx_leaf[i];
	}
	idx_leaf &= (1 << (params.h / params.d)) - 1;

	setTreeAddress(ADRS, idx_tree);
	setTypeAndClear(ADRS, FORS_TREE);
	setKeyPairAddress(ADRS, idx_leaf);

	int* SIG_FORS = fors_sign(params, md, SK_seed, PK_seed, ADRS);

	for (int i = 0; i < treeSigSize * params.k; i++) SIG[params.n + i] = SIG_FORS[i];

	int* PK_FORS = fors_pkFromSig(params, SIG_FORS, md, PK_seed, ADRS);

	int* SIG_HT = ht_sign(params, PK_FORS, SK_seed, PK_seed, idx_tree, idx_leaf);

	for (int i = 0; i < xmssSigLen * params.d; i++) SIG[params.n + treeSigSize * params.k + i] = SIG_HT[i];

	free(ADRS);
	free(R);
	free(digest);
	free(SIG_FORS);
	free(PK_FORS);
	free(SIG_HT);

	return SIG;
}

bool slh_verify_internal(struct parameters params, int* M, int M_len, int* SIG, int* PK) {
	int* ADRS = calloc(32, sizeof(int));

	int* R = SIG;
	int* SIG_FORS = SIG + params.n;
	int* SIG_HT = SIG + (1 + params.k * (1 + params.a)) * params.n;
	
	int* PK_seed = PK;
	int* PK_root = PK + params.n;

	int* digest = H_msg(params, R, PK_seed, PK_root, M, M_len);
	int* md = digest;
	int* tmp_idx_tree = digest + (params.k * params.a + 7) / 8;
	int* tmp_idx_leaf = tmp_idx_tree + (params.h - params.h / params.d + 7) / 8;

	ulong idx_tree = 0;
	for (int i = 0; i < (params.h - params.h / params.d + 7) / 8; i++) {
		idx_tree *= 256;
		idx_tree += tmp_idx_tree[i];
	}
	if ((params.h - params.h / params.d) != 64) {
		idx_tree &= (((ulong) 1) << (params.h - params.h / params.d)) - 1;
	}

	int idx_leaf = 0;
	for (int i = 0; i < (params.h / params.d + 7) / 8; i++) {
		idx_leaf *= 256;
		idx_leaf += tmp_idx_leaf[i];
	}
	idx_leaf &= (1 << (params.h / params.d)) - 1;

	setTreeAddress(ADRS, idx_tree);
	setTypeAndClear(ADRS, FORS_TREE);
	setKeyPairAddress(ADRS, idx_leaf);
	
	int* PK_FORS = fors_pkFromSig(params, SIG_FORS, md, PK_seed, ADRS);

	bool matches = ht_verify(params, PK_FORS, SIG_HT, PK_seed, idx_tree, idx_leaf, PK_root);

	free(ADRS);
	free(digest);
	free(PK_FORS);

	return matches;
}