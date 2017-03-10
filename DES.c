#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#define NUM 1024*1024*11

char stInputKey[10];
char stSubKeys[16][48];
char stCiphertextRaw[64];
char stPlaintextRaw[64];
char stCiphertextInBytes[8];
char stPlaintextInBytes[8];

char stCiphertextInBinary[65];
char stCiphertextInHex[17];
char stPlaintext[9];

char stFCiphertextAnyLength[8192];
char stFPlaintextAnyLength[8192];

const static char PC1_Table[56] = {
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

const static char PC2_Table[48] = {
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};
const static char Shift_Table[16] = {
	1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};

const static char IP_Table[64] = {
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

const static char E_Table[48] = {
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};
//  S-boxes
const static char S_Box[8][4][16] = {
	// S1
	14,  4,	13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
	0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
	4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
	15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
	// S2
	15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
	3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
	0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
	13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
	// S3
	10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
	13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
	13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
	1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
	// S4
	7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
	13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
	10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
	3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
	// S5
	2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
	14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
	4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
	11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
	// S6
	12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
	10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
	9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
	4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
	// S7
	4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
	13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
	1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
	6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
	// S8
	13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
	1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
	7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
	2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
};

const static char P_Table[32] = {
	16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
	2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25
};

const static char IPR_Table[64] = {
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
};
void Initialize();
void InitializeKey(char* srcBytes);
void EncryptData(char* _srcBytes);
void DecryptData(char* _srcBytes);
void EncryptAnyLength(char* _srcBytes,unsigned int _bytesLength);
void DecryptAnyLength(char* _srcBytes,unsigned int _bytesLength);
void Bytes2Bits(char *srcBytes, char* dstBits, unsigned int sizeBits);
void Bits2Bytes(char *dstBytes, char* srcBits, unsigned int sizeBits);
void Int2Bits(unsigned int srcByte, char* dstBits);
void Bits2Hex(char *dstHex, char* srcBits, unsigned int sizeBits);
void Hex2Bits(char *srcHex, char* dstBits, unsigned int sizeBits);
char* GetCiphertextInHex();
char* GetCiphertextInBytes();
char* GetCiphertextAnyLength();
char* GetPlaintextAnyLength();
void CreateSubKey(char* st_56key);
void FunctionF(char* st_Li,char* st_Ri,unsigned int iKey);
void InitialPermuteData(char* _src,char* _dst);
void ExpansionR(char* _src,char* _dst);
void XOR(char* stParam1,char* stParam2, unsigned int uiParamLength,
char* stReturnValueBuffer);
void PermutationFuncS(char* _src48, char* _dst32);
void PermutationP(char* _src,char* _dst);
void creatrandomnum();
void Initialize()
{
	memset(stCiphertextRaw,0,64);
	memset(stPlaintextRaw,0,64);
	memset(stCiphertextInBytes,0,8);
	memset(stPlaintextInBytes,0,8);
	memset(stCiphertextInBinary,0,65);
	memset(stCiphertextInHex,0,17);
	memset(stPlaintext,0,9);
	memset(stFCiphertextAnyLength,0,8192);
	memset(stCiphertextInHex,0,8192);
}

void InitializeKey(char* srcBytes)
{
	//convert 8 char-bytes key to 64 binary-bits
	char st_64key[64] = {0};
	char st_56key[56] = {0};
	int k=0;
	Bytes2Bits(srcBytes,st_64key,64);
	//PC 1
	for(k=0;k<56;k++)
	{
		st_56key[k] = st_64key[PC1_Table[k]-1];
	}
	CreateSubKey(st_56key);
}

void CreateSubKey(char* st_56key)
{
	char stTmpL[28] = {0};
	char stTmpR[28] = {0};
	char stCi[28] = {0};
	char stDi[28] = {0};
	char stTmp56[56] = {0};
	int i=0,j=0;

	memcpy(stTmpL,st_56key,28);
	memcpy(stTmpR,st_56key + 28,28);

	for(i=0;i<16;i++)
	{
		//左半部分左移28位
		memcpy(stCi,stTmpL + Shift_Table[i],28 - Shift_Table[i]);
		memcpy(stCi + 28 - Shift_Table[i],stTmpL,Shift_Table[i]);
		//右半部分左移28位
		memcpy(stDi,stTmpR + Shift_Table[i],28 - Shift_Table[i]);
		memcpy(stDi + 28 - Shift_Table[i],stTmpR,Shift_Table[i]);

		//左移后的56位进行pc2置换
		memcpy(stTmp56,stCi,28);
		memcpy(stTmp56 + 28,stDi,28);
		for(j=0;j<48;j++)
		{
			stSubKeys[i][j] = stTmp56[PC2_Table[j]-1];
		}
		//产生新的左半部分和右半部分
		memcpy(stTmpL,stCi,28);
		memcpy(stTmpR,stDi,28);
	}
}

void EncryptData(char* _srcBytes)
{
	char stSrcBits[64] = {0};
	char st_IP[64] = {0};
	char st_Li[32] = {0};
	char st_Ri[32] = {0};
	char st_Final64[64] = {0};
	int i=0,j=0;

	Bytes2Bits(_srcBytes,stSrcBits,64);
	InitialPermuteData(stSrcBits,st_IP);//IP变换
	memcpy(st_Li,st_IP,32);
	memcpy(st_Ri,st_IP + 32,32);

	for(i=0;i<16;i++)
	{
		FunctionF(st_Li,st_Ri,i);
	}
	memcpy(st_Final64,st_Ri,32);//得到未逆变换的密文
	memcpy(st_Final64 + 32,st_Li,32);

	//逆IP变换
	for(j=0;j<64;j++)
	{
		stCiphertextRaw[j] = st_Final64[IPR_Table[j]-1];
	}
	Bits2Bytes(stCiphertextInBytes,stCiphertextRaw,64);
}

void DecryptData(char* _srcBytes)
{
	char stSrcBits[64] = {0};
	char st_IP[64] = {0};
	char st_Li[32] = {0};
	char st_Ri[32] = {0};
	char st_Final64[64] = {0};
	int i=0,j=0;
	Bytes2Bits(_srcBytes,stSrcBits,64);

	InitialPermuteData(stSrcBits,st_IP);//进行IP置换
	//将64位字节分成两部分
	memcpy(st_Ri,st_IP,32); //改变左右32位的位置
	memcpy(st_Li,st_IP + 32,32);

	for(i=0;i<16;i++)//进行16轮的f函数和异或操作
	{
		FunctionF(st_Ri,st_Li,15-i);
	}
	memcpy(st_Final64,st_Li,32);
	memcpy(st_Final64 + 32,st_Ri,32);

	for(j=0;j<64;j++)// 逆IP置换
	{
		stPlaintextRaw[j] = st_Final64[IPR_Table[j]-1];
	}
	Bits2Bytes(stPlaintextInBytes,stPlaintextRaw,64);
}

void FunctionF(char* st_Li,char* st_Ri,unsigned int iKey)
{
	char st_48R[48] = {0};
	char st_xor48[48] = {0};
	char st_P32[32] = {0};
	char st_Rii[32] = {0};
	char st_Key[48] = {0};
	char s_Compress32[32] = {0};
	memcpy(st_Key,stSubKeys[iKey],48);
	ExpansionR(st_Ri,st_48R); //将32位字符串扩展成48位
	XOR(st_48R,st_Key,48,st_xor48);

	PermutationFuncS(st_xor48,s_Compress32);//s盒子
	PermutationP(s_Compress32,st_P32); //IP逆变换
	XOR(st_P32,st_Li,32,st_Rii);
	memcpy(st_Li,st_Ri,32);
	memcpy(st_Ri,st_Rii,32);
}

void InitialPermuteData(char* _src,char* _dst)
{
	//IP变换
	int i=0;
	for(i=0;i<64;i++)
	{
		_dst[i] = _src[IP_Table[i]-1];
	}
}

void ExpansionR(char* _src,char* _dst)
{
	int i=0;
	for(i=0;i<48;i++)
	{
		_dst[i] = _src[E_Table[i]-1];
	}
}

void XOR(char* stParam1,char* stParam2, unsigned int uiParamLength, char* stReturnValueBuffer)
{
	unsigned int i=0;
	for(i=0; i<uiParamLength; i++)
	{
		stReturnValueBuffer[i] = stParam1[i] ^ stParam2[i];
	}
}

void PermutationFuncS(char* _src48, char* _dst32)
{
	char bTemp[8][6]={0};
	char dstBits[4]={0};
	int i=0,iX=0,iY=0,j=0;

	for(i=0;i<8;i++)
	{
		memcpy(bTemp[i],_src48+i*6,6);
		iX = (bTemp[i][0])*2 + (bTemp[i][5]);
		iY = 0;
		for(j=1;j<5;j++)
		{
			iY += bTemp[i][j]<<(4-j);
		}
		Int2Bits(S_Box[i][iX][iY], dstBits);
		memcpy(_dst32 + i * 4, dstBits, 4);
	}

}

void PermutationP(char* _src,char* _dst)
{
	int i=0;
	for(i=0;i<32;i++)
	{
		_dst[i] = _src[P_Table[i]-1];
	}
}

void Bytes2Bits(char *srcBytes, char* dstBits, unsigned int sizeBits)
{
	unsigned int i=0;
	for(i=0; i < sizeBits; i++)
		dstBits[i] = ((srcBytes[i>>3]<<(i&7)) & 128)>>7;
}

void Bits2Bytes(char *dstBytes, char* srcBits, unsigned int sizeBits)
{
	unsigned int i=0;
	memset(dstBytes,0,sizeBits>>3);
	for(i=0; i < sizeBits; i++)
		dstBytes[i>>3] |= (srcBits[i] << (7 - (i & 7)));
}

void Int2Bits(unsigned int _src, char* dstBits)
{
	unsigned int i=0;
	for(i=0; i < 4; i++)
		dstBits[i] = ((_src<<i) & 8)>>3;
}

void Bits2Hex(char *dstHex, char* srcBits, unsigned int sizeBits)
{
	unsigned int i=0,j=0;
	memset(dstHex,0,sizeBits>>2);
	for(i=0; i < sizeBits; i++) //convert to int 0-15
		dstHex[i>>2] += (srcBits[i] << (3 - (i & 3)));
	for(j=0;j < (sizeBits>>2);j++)
		dstHex[j] += dstHex[j] > 9 ? 55 : 48; //convert to char '0'-'F'
}

void Hex2Bits(char *srcHex, char* dstBits, unsigned int sizeBits)
{
	unsigned int i=0,j=0;
	memset(dstBits,0,sizeBits);
	for(i=0;i < (sizeBits>>2);i++)
		srcHex[i] -= srcHex[i] > 64 ? 55 : 48; //convert to char int 0-15
	for(j=0; j < sizeBits; j++)
		dstBits[j] = ((srcHex[j>>2]<<(j&3)) & 15) >> 3;

}



char* GetCiphertextInHex()
{
	Bits2Hex(stCiphertextInHex,stCiphertextRaw,64);
	stCiphertextInHex[16] = '\0';
	return stCiphertextInHex;
}

char* GetCiphertextInBytes()
{
	return stCiphertextInBytes;
}



char* GetCiphertextAnyLength()
{
	return stFCiphertextAnyLength;
}

char* GetPlaintextAnyLength()
{
	return stFPlaintextAnyLength;
}

void EncryptAnyLength(char* _srcBytes,unsigned int _bytesLength)
{
	int iParts=0,iResidue=0,i=0;
	char stLast8Bits[8] = {0};

	if(_bytesLength == 8)
	{
		EncryptData(_srcBytes);
		memcpy(stFCiphertextAnyLength,stCiphertextInBytes,8);
		stFCiphertextAnyLength[8] = '\0';
	}
	else if(_bytesLength < 8)
	{
		char _temp8bytes[8] = {0};
		memcpy(_temp8bytes,_srcBytes,_bytesLength);
		EncryptData(_temp8bytes);
		memcpy(stFCiphertextAnyLength,stCiphertextInBytes,8);
		stFCiphertextAnyLength[8] = '\0'; //短块处理，000'/n'
	}
	else if(_bytesLength > 8)
	{
		iParts = _bytesLength>>3;
		iResidue = _bytesLength % 8;

		for(i=0;i<iParts;i++)//将8的整数倍的位数进行每8个一次的加密
		{
			memcpy(stLast8Bits,_srcBytes + (i<<3),8);
			EncryptData(stLast8Bits);
			memcpy(stFCiphertextAnyLength + (i<<3),stCiphertextInBytes,8);
		}
		memset(stLast8Bits,0,8);
		memcpy(stLast8Bits,_srcBytes + (iParts<<3),iResidue);//对多余的小于8个的数进行加密

		EncryptData(stLast8Bits);
		memcpy(stFCiphertextAnyLength + (iParts<<3),stCiphertextInBytes,8);
		stFCiphertextAnyLength[((iParts+1)<<3)] = '\0';
	}
}

void DecryptAnyLength(char* _srcBytes,unsigned int _bytesLength)
{
	int iParts=0,iResidue=0,i=0;
	char stLast8Bits[8] = {0};
	char _temp8bytes[8] = {0};

	if(_bytesLength == 8)
	{
		DecryptData(_srcBytes);
		memcpy(stFPlaintextAnyLength,stPlaintextInBytes,8);
		stFPlaintextAnyLength[8] = '\0';
	}
	else if(_bytesLength < 8)
	{
		memcpy(_temp8bytes,_srcBytes,8);
		DecryptData(_temp8bytes);
		memcpy(stFPlaintextAnyLength,stPlaintextInBytes,_bytesLength);
		stFPlaintextAnyLength[_bytesLength] = '\0';
	}
	else if(_bytesLength > 8)
	{
		iParts = _bytesLength>>3;
		iResidue = _bytesLength % 8;
		for(i=0;i<iParts;i++)
		{
			memcpy(stLast8Bits,_srcBytes + (i<<3),8);
			DecryptData(stLast8Bits);
			memcpy(stFPlaintextAnyLength + (i<<3),stPlaintextInBytes,8);
		}
		if(iResidue != 0)
		{
			memset(stLast8Bits,0,8);
			memcpy(stLast8Bits,_srcBytes + (iParts<<3),8);
			DecryptData(stLast8Bits);
			memcpy(stFPlaintextAnyLength + (iParts<<3),stPlaintextInBytes,iResidue);
		}
		stFPlaintextAnyLength[_bytesLength] = '\0';
	}
}
int CheckKey()
{
	char A[6],B[6];
	int i;
	Bits2Bytes(A,stSubKeys[0],48);
	for( i=1;i<16;i++)
	{
		Bits2Bytes(B,stSubKeys[i],48);
		if ( 0 != memcmp((void*)A,(void*)B,6) )
		{
			return 1;
		}
		else
		{
			memcpy((void*)A,(void*)B,6);
		}
	}
	return 0;
}

void creatrandomnum()
{
    FILE *IN,*OUT;
    char stInputCiphertext[8] = {0};
    int temp;
    char p,filein[8]={0};
    if((IN=fopen("D:\\learning\\密码学课设\\10.dat","rb"))==NULL)
    exit(-1);
    if((OUT=fopen("D:\\learning\\密码学课设\\10DES.dat","wb"))==NULL)
    exit(-1);
    while(!feof(IN))
    {
        for(temp=0;temp<=7;temp++)
        {
            if(!feof(IN))
            filein[temp]=getc(IN);
        }
        EncryptAnyLength(filein,8);
        memcpy(stInputCiphertext,GetCiphertextAnyLength(),8);
        for(temp=0;temp<=7;temp++)
        {
            fputc(stInputCiphertext[temp],OUT);
        }
    }
    fclose(OUT);
    fclose(IN);
}


void main()
{
	char stInputKey[10] = {0};
	char stInputPlaintext[1024] = {0};
	char stInputCiphertext[1024] = {0};
	char stInputCiphertextInHex[2048] = {0};
	char stCiphertextInBit[8196] = {0};
	char ch;

	int temp = 0;

    printf("欢迎使用DES加密工具\n请输入以下指令:\n");
	printf("a : 加密\n");
	printf("b : 解密\n");
	printf("d : 生成10M随机数\n");
	printf("# : 退出\n");

while ((ch=getchar())!='#')
{
	if('\n'==ch)
		continue;
	switch(ch)
	{
	case 'a':
	case 'A':printf("请输入密钥(1-8 bytes):\n");
			 scanf("%s",stInputKey);
			 InitializeKey(stInputKey);
			 if (1 == CheckKey())
			 {
	         memset(stInputPlaintext,0,1024); //将存储明文的数组清零
			 printf("请输入明文(1-1024 bytes):\n");
			 scanf("%s",stInputPlaintext);
			 temp = strlen(stInputPlaintext);
			 EncryptAnyLength(stInputPlaintext,temp);
			 temp = temp % 8 == 0 ? temp : ((temp >> 3 ) + 1)  << 3;//保证得到的明文个数是8的整数倍
			 memcpy(stInputCiphertext,GetCiphertextAnyLength(),temp);
			 Bytes2Bits(stInputCiphertext,stCiphertextInBit,temp << 3);
			 Bits2Hex(stInputCiphertextInHex,stCiphertextInBit,temp << 3);
		//stInputCiphertextInHex[temp % 8 == 0 ? temp << 1 : ((temp >> 3) + 1) << 4] = '\0';
			 stInputCiphertextInHex[temp << 1] = 0;
			 printf("加密之后得到的16进制密文:\n%s\n\n\n",stInputCiphertextInHex);
			 }
			 else
			 {
				 printf("产生秘钥错误!\n");
			 }
			 break;
	case 'b':
	case 'B':printf("请输入密钥(1-8 bytes):\n");
			scanf("%s",stInputKey);
            InitializeKey(stInputKey);
			if (1 == CheckKey())
			{
			memset(stInputCiphertextInHex,0,2048);
			memset(stCiphertextInBit,0,8196);
			printf("请输入16进制的密文 (1-2048 位):\n");
			scanf("%s",stInputCiphertextInHex);
			temp = strlen(stInputCiphertextInHex);
			Hex2Bits(stInputCiphertextInHex,stCiphertextInBit,temp << 2);
			Bits2Bytes(stInputCiphertext,stCiphertextInBit,temp << 2);
			DecryptAnyLength(stInputCiphertext,temp >> 1);
			printf("解密后得到的明文为:\n%s\n\n\n", GetPlaintextAnyLength());
			}
			else
			{
				printf("Erroe this's a weakkey!\n");
			}
			break;
		case 'd':
		case 'D':creatrandomnum();
		         break;
	    default:
		    printf("That's a stumper!\n");
	}
	printf("请继续选择接下来的操作.\n");
}
printf("再见!\n");
getchar();
}
