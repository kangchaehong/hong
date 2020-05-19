#include<stdio.h>
#include<stdlib.h>

#include "aes256enc.h"

unsigned char ccipherkey[32] = { 0x60,0x3D,0xEB,0x10,0x15,0xCA,0x71,0xBE,0x2B,0x73,0xAE,0xF0,0x85,0x7D,0x77,0x81,
0x1F,0x35,0x2C,0x07,0x3B,0x61,0x08,0xD7,0x2D,0x98,0x10,0xA3,0x09,0x14,0xDF,0xF4 };
//암호화 키 지정, 키 값은 무작위로 되도 상관없음
// @@@ ccipherkey 값도 바뀌어야 하지않나?
int main()
{
	int l;
	KeyExpansion(ccipherkey);//KeyExpansion 호출 
							 // 각 round에 사용하는 round key를 생성하기 위함

	unsigned char inmsg[16] = { 0xDC,0x03,0x6D,0xFF,0x85,0x2F,0xB2,0x18,0xC9,0xFC,0xC0,0xCB,0x50,0xC0,0xA6,0xC3 };//암호화할 Plain bytestream

	AES256(inmsg, 16);//암호화 실행

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