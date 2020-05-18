#include<stdlib.h>
#include<stdio.h>

static unsigned char sbox[16][16] = {
{99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118},
{202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192},
{183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 216,  49,  21},
{4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 235,  39, 178, 117},
{9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132},
{83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207},
{208, 239, 170, 251,  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168},
{81, 163,  64, 143, 146, 157,  56, 245, 188, 182, 218,  33,  16, 255, 243, 210},
{205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61, 100,  93,  25, 115},
{96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219},
{224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121},
{231, 200,  55, 109, 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8},
{186, 120,  37,  46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138},
{112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158},
{225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223},
{140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22}
};

static unsigned char encrypt[4][4];
unsigned char encrypted_msg[16];
static unsigned char roundkey[176]; //@@@
int i, j;

int SubBytes() {
	char tempx, tempy;
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			tempx = encrypt[i][j];
			tempy = tempx;
			encrypt[i][j] = sbox[(tempx & 0xF0) >> 4][tempy & 0x0F];
		}
	}
	return 0;
}

int ShiftRows() {
	unsigned char temp;
	temp = encrypt[1][0];
	encrypt[1][0] = encrypt[1][1];
	encrypt[1][1] = encrypt[1][2];
	encrypt[1][2] = encrypt[1][3];
	encrypt[1][3] = temp;

	temp = encrypt[2][0];
	encrypt[2][0] = encrypt[2][2];
	encrypt[2][2] = temp;
	temp = encrypt[2][1];
	encrypt[2][1] = encrypt[2][3];
	encrypt[2][3] = temp;

	temp = encrypt[3][0];
	encrypt[3][0] = encrypt[3][3];
	encrypt[3][3] = encrypt[3][2];
	encrypt[3][2] = encrypt[3][1];
	encrypt[3][1] = temp;

	return 0;
}

int MixColumns() {
	unsigned char copyarr[4], res[4];
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			res[j] = (encrypt[j][i] << 1) ^ (0x1B * (encrypt[j][i] >> 7));
			copyarr[j] = encrypt[j][i];
		}
		encrypt[0][i] = res[0] ^ copyarr[3] ^ copyarr[2] ^ res[1] ^ copyarr[1];
		encrypt[1][i] = res[1] ^ copyarr[0] ^ copyarr[3] ^ res[2] ^ copyarr[2];
		encrypt[2][i] = res[2] ^ copyarr[1] ^ copyarr[0] ^ res[3] ^ copyarr[3];
		encrypt[3][i] = res[3] ^ copyarr[2] ^ copyarr[1] ^ res[0] ^ copyarr[0];
	}
	return 0;
}

int AddRoundKey(int round) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			encrypt[j][i] = encrypt[j][i] ^ roundkey[(16 * round) + (4 * i) + j];
		}
	}
	return 0;
}

int KeyExpansion(unsigned char cipherkey[]) { //cipherkey 총 128bit / 하나당 8bit
	// AES 128 경우 roundkey : 44word , 256인 경우 : 60word
	int indic = 0;
	unsigned char temp[4];
	unsigned char t;
	unsigned char Rcon[11] = { 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
	// Rcon : Round 상수
	// Rcon[0] -> 무의미한것
	// @@@@@
	while (indic < 8) { // 
		for (int j = 0; j < 4; j++) {
			roundkey[4 * indic + j] = cipherkey[4 * indic + j];
		}
		indic = indic + 1;
	}
	indic = 8;

	// @@@@@@
	while (indic < 60) {
		for (int j = 0; j < 4; j++) {
			temp[j] = roundkey[4 * (indic - 1) + j];
		}
		if (indic % 8 == 0) {
			t = temp[0];
			temp[0] = sbox[(temp[1] & 0xF0) >> 4][temp[1] & 0x0F];
			temp[1] = sbox[(temp[2] & 0xF0) >> 4][temp[2] & 0x0F];
			temp[2] = sbox[(temp[3] & 0xF0) >> 4][temp[3] & 0x0F];
			temp[3] = sbox[(t & 0xF0) >> 4][t & 0x0F];
			temp[0] = temp[0] ^ Rcon[indic / 4];
		}
		for (int j = 0; j < 4; j++) {
			roundkey[4 * indic + j] = roundkey[4 * (indic - 4) + j] ^ temp[j];
		}
		indic = indic + 1;
	}
	return 0;
}

unsigned char* AES256(unsigned char plainstream[], int streamlen) //state로 변환
{
	char eostream = 0;
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			if (eostream == 0) {
				if (((4 * i) + j + 1) >= streamlen) {
					eostream = 1;
					continue;
				}
				encrypt[j][i] = plainstream[(4 * i) + j];
			}
			else {
				encrypt[j][i] = 0;
			}
		}
	}
	AddRoundKey(0);
	for (int round = 1; round < 14; round++) // aes256 round는 14
	{
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(round);
	}
	SubBytes();
	ShiftRows();
	AddRoundKey(14);

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			encrypted_msg[(4 * i) + j] = encrypt[j][i];
		}
	}

	return encrypted_msg;
}