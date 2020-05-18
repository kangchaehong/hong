#pragma once

static unsigned char sbox[16][16];

static unsigned char encrypt[4][4];
unsigned char encrypted_msg[16];//��ȣȭ ��� ����Ǵ� �迭
static unsigned char roundkey[176];

int SubBytes();

int ShiftRows();

int MixColumns();

int AddRoundKey(int round);

int KeyExpansion(unsigned char cipherkey[]);
//ó�� ���� ��, ��ȣȭ Ű ���� �� �ʼ� ����, Input�� 16����Ʈ ��ȣȭ Ű

unsigned char* AES256(unsigned char plainstream[], int streamlen);
//��ȣȭ �Լ�, Input�� ��ȣȭ�� �迭�� �迭�� ����
