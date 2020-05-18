#include<stdio.h>
#include<stdlib.h>

#include "aes256enc.h"

unsigned char ccipherkey[16] = { 0xE1,0x53,0xFB,0x0E,0x16,0x12,0x75,0x48,0x5A,0xB2,0x17,0x96,0xC4,0x2F,0x76,0xD1 };//암호화 키 지정
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