#include<stdio.h>
#include<stdlib.h>

#include "aes256enc.h"

unsigned char ccipherkey[16] = { 0xE1,0x53,0xFB,0x0E,0x16,0x12,0x75,0x48,0x5A,0xB2,0x17,0x96,0xC4,0x2F,0x76,0xD1 };//��ȣȭ Ű ����
// @@@ ccipherkey ���� �ٲ��� �����ʳ�?
int main()
{
	int l;
	KeyExpansion(ccipherkey);//KeyExpansion ȣ�� 
							 // �� round�� ����ϴ� round key�� �����ϱ� ����

	unsigned char inmsg[16] = { 0xDC,0x03,0x6D,0xFF,0x85,0x2F,0xB2,0x18,0xC9,0xFC,0xC0,0xCB,0x50,0xC0,0xA6,0xC3 };//��ȣȭ�� Plain bytestream

	AES256(inmsg, 16);//��ȣȭ ����

	for (l = 0; l < 16; l++) {
		if (encrypted_msg[l] >= 0x10) {
			printf("%X", encrypted_msg[l]);
		}
		else {
			printf("0%X", encrypted_msg[l]);
		}
	}
	printf("\n");
	return 0;
}