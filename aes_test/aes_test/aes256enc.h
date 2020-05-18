#pragma once

static unsigned char sbox[16][16];

static unsigned char encrypt[4][4];
unsigned char encrypted_msg[16];//암호화 결과 저장되는 배열
static unsigned char roundkey[176];

int SubBytes();

int ShiftRows();

int MixColumns();

int AddRoundKey(int round);

int KeyExpansion(unsigned char cipherkey[]);
//처음 시작 시, 암호화 키 변경 시 필수 실행, Input은 16바이트 암호화 키

unsigned char* AES256(unsigned char plainstream[], int streamlen);
//암호화 함수, Input은 암호화할 배열과 배열의 길이
