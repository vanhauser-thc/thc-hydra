/* aes.h */

/* ---------- See examples at end of this file for typical usage -------- */

/* AES Cipher header file for ANSI C Submissions
	Lawrence E. Bassham III
	Computer Security Division
	National Institute of Standards and Technology

	This sample is to assist implementers developing to the
Cryptographic API Profile for AES Candidate Algorithm Submissions.
Please consult this document as a cross-reference.
	
	ANY CHANGES, WHERE APPROPRIATE, TO INFORMATION PROVIDED IN THIS FILE
MUST BE DOCUMENTED. CHANGES ARE ONLY APPROPRIATE WHERE SPECIFIED WITH
THE STRING "CHANGE POSSIBLE". FUNCTION CALLS AND THEIR PARAMETERS
CANNOT BE CHANGED. STRUCTURES CAN BE ALTERED TO ALLOW IMPLEMENTERS TO
INCLUDE IMPLEMENTATION SPECIFIC INFORMATION.
*/

/* Includes:
	Standard include files
*/

#include	<stdio.h>
#include	"platform.h"			/* platform-specific defines */

/*	Defines:
		Add any additional defines you need
*/

#define 	DIR_ENCRYPT 	0 		/* Are we encrpyting? */
#define 	DIR_DECRYPT 	1 		/* Are we decrpyting? */
#define 	MODE_ECB 		1 		/* Are we ciphering in ECB mode? */
#define 	MODE_CBC 		2 		/* Are we ciphering in CBC mode? */
#define 	MODE_CFB1 		3 		/* Are we ciphering in 1-bit CFB mode? */

#define 	TRUE 			1
#define 	FALSE 			0

#define 	BAD_KEY_DIR 		-1	/* Key direction is invalid (unknown value) */
#define 	BAD_KEY_MAT 		-2	/* Key material not of correct length */
#define 	BAD_KEY_INSTANCE 	-3	/* Key passed is not valid */
#define 	BAD_CIPHER_MODE 	-4 	/* Params struct passed to cipherInit invalid */
#define 	BAD_CIPHER_STATE 	-5 	/* Cipher in wrong state (e.g., not initialized) */

/* CHANGE POSSIBLE: inclusion of algorithm specific defines */
/* TWOFISH specific definitions */
#define		MAX_KEY_SIZE		64	/* # of ASCII chars needed to represent a key */
#define		MAX_IV_SIZE			16	/* # of bytes needed to represent an IV */
#define		BAD_INPUT_LEN		-6	/* inputLen not a multiple of block size */
#define		BAD_PARAMS			-7	/* invalid parameters */
#define		BAD_IV_MAT			-8	/* invalid IV text */
#define		BAD_ENDIAN			-9	/* incorrect endianness define */
#define		BAD_ALIGN32			-10	/* incorrect 32-bit alignment */

#define		BLOCK_SIZE			128	/* number of bits per block */
#define		MAX_ROUNDS			 16	/* max # rounds (for allocating subkey array) */
#define		ROUNDS_128			 16	/* default number of rounds for 128-bit keys*/
#define		ROUNDS_192			 16	/* default number of rounds for 192-bit keys*/
#define		ROUNDS_256			 16	/* default number of rounds for 256-bit keys*/
#define		MAX_KEY_BITS		256	/* max number of bits of key */
#define		MIN_KEY_BITS		128	/* min number of bits of key (zero pad) */
#define		VALID_SIG	 0x48534946	/* initialization signature ('FISH') */
#define		MCT_OUTER			400	/* MCT outer loop */
#define		MCT_INNER		  10000	/* MCT inner loop */
#define		REENTRANT			  1	/* nonzero forces reentrant code (slightly slower) */

#define		INPUT_WHITEN		0	/* subkey array indices */
#define		OUTPUT_WHITEN		( INPUT_WHITEN + BLOCK_SIZE/32)
#define		ROUND_SUBKEYS		(OUTPUT_WHITEN + BLOCK_SIZE/32)	/* use 2 * (# rounds) */
#define		TOTAL_SUBKEYS		(ROUND_SUBKEYS + 2*MAX_ROUNDS)

/* Typedefs:
	Typedef'ed data storage elements. Add any algorithm specific
	parameters at the bottom of the structs as appropriate.
*/

typedef unsigned char BYTE;
typedef	unsigned long DWORD;		/* 32-bit unsigned quantity */
typedef DWORD fullSbox[4][256];

/* The structure for key information */
typedef struct 
	{
	BYTE direction;					/* Key used for encrypting or decrypting? */
#if ALIGN32
	BYTE dummyAlign[3];				/* keep 32-bit alignment */
#endif
	int  keyLen;					/* Length of the key */
	char keyMaterial[MAX_KEY_SIZE+4];/* Raw key data in ASCII */

	/* Twofish-specific parameters: */
	DWORD keySig;					/* set to VALID_SIG by makeKey() */
	int	  numRounds;				/* number of rounds in cipher */
	DWORD key32[MAX_KEY_BITS/32];	/* actual key bits, in dwords */
	DWORD sboxKeys[MAX_KEY_BITS/64];/* key bits used for S-boxes */
	DWORD subKeys[TOTAL_SUBKEYS];	/* round subkeys, input/output whitening bits */
#if REENTRANT
	fullSbox sBox8x32;				/* fully expanded S-box */
  #if defined(COMPILE_KEY) && defined(USE_ASM)
#undef	VALID_SIG
#define	VALID_SIG	 0x504D4F43		/* 'COMP':  C is compiled with -DCOMPILE_KEY */
	DWORD cSig1;					/* set after first "compile" (zero at "init") */
	void *encryptFuncPtr;			/* ptr to asm encrypt function */
	void *decryptFuncPtr;			/* ptr to asm decrypt function */
	DWORD codeSize;					/* size of compiledCode */
	DWORD cSig2;					/* set after first "compile" */
	BYTE  compiledCode[5000];		/* make room for the code itself */
  #endif
#endif
	} keyInstance;

/* The structure for cipher information */
typedef struct 
	{
	BYTE  mode;						/* MODE_ECB, MODE_CBC, or MODE_CFB1 */
#if ALIGN32
	BYTE dummyAlign[3];				/* keep 32-bit alignment */
#endif
	BYTE  IV[MAX_IV_SIZE];			/* CFB1 iv bytes  (CBC uses iv32) */

	/* Twofish-specific parameters: */
	DWORD cipherSig;				/* set to VALID_SIG by cipherInit() */
	DWORD iv32[BLOCK_SIZE/32];		/* CBC IV bytes arranged as dwords */
	} cipherInstance;

/* Function protoypes */
int makeKey(keyInstance *key, BYTE direction, int keyLen, char *keyMaterial);

int cipherInit(cipherInstance *cipher, BYTE mode, char *IV);

int blockEncrypt(cipherInstance *cipher, keyInstance *key, BYTE *input,
				int inputLen, BYTE *outBuffer);

int blockDecrypt(cipherInstance *cipher, keyInstance *key, BYTE *input,
				int inputLen, BYTE *outBuffer);

int	reKey(keyInstance *key);	/* do key schedule using modified key.keyDwords */

/* API to check table usage, for use in ECB_TBL KAT */
#define		TAB_DISABLE			0
#define		TAB_ENABLE			1
#define		TAB_RESET			2
#define		TAB_QUERY			3
#define		TAB_MIN_QUERY		50
int TableOp(int op);


#define		CONST				/* helpful C++ syntax sugar, NOP for ANSI C */

#if BLOCK_SIZE == 128			/* optimize block copies */
#define		Copy1(d,s,N)	((DWORD *)(d))[N] = ((DWORD *)(s))[N]
#define		BlockCopy(d,s)	{ Copy1(d,s,0);Copy1(d,s,1);Copy1(d,s,2);Copy1(d,s,3); }
#else
#define		BlockCopy(d,s)	{ memcpy(d,s,BLOCK_SIZE/8); }
#endif


#ifdef TEST_2FISH
/*						----- EXAMPLES -----

Unfortunately, the AES API is somewhat clumsy, and it is not entirely
obvious how to use the above functions.  In particular, note that
makeKey() takes an ASCII hex nibble key string (e.g., 32 characters
for a 128-bit key), which is rarely the way that keys are internally
represented.  The reKey() function uses instead the keyInstance.key32
array of key bits and is the preferred method.  In fact, makeKey()
initializes some internal keyInstance state, then parse the ASCII
string into the binary key32, and calls reKey().  To initialize the
keyInstance state, use a 'dummy' call to makeKey(); i.e., set the
keyMaterial parameter to NULL.  Then use reKey() for all key changes.
Similarly, cipherInit takes an IV string in ASCII hex, so a dummy setup
call with a null IV string will skip the ASCII parse.  

Note that CFB mode is not well tested nor defined by AES, so using the
Twofish MODE_CFB it not recommended.  If you wish to implement a CFB mode,
build it external to the Twofish code, using the Twofish functions only
in ECB mode.

Below is a sample piece of code showing how the code is typically used
to set up a key, encrypt, and decrypt.  Error checking is somewhat limited
in this example.  Pseudorandom bytes are used for all key and text.

If you compile TWOFISH2.C or TWOFISH.C as a DOS (or Windows Console) app
with this code enabled, the test will be run.  For example, using
Borland C, you would compile using:
  BCC32 -DTEST_2FISH twofish2.c
to run the test on the optimized code, or
  BCC32 -DTEST_2FISH twofish.c
to run the test on the pedagogical code.

*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define MAX_BLK_CNT		4		/* max # blocks per call in TestTwofish */
int TestTwofish(int mode,int keySize) /* keySize must be 128, 192, or 256 */
	{							/* return 0 iff test passes */
	keyInstance    ki;			/* key information, including tables */
	cipherInstance ci;			/* keeps mode (ECB, CBC) and IV */
	BYTE  plainText[MAX_BLK_CNT*(BLOCK_SIZE/8)];
	BYTE cipherText[MAX_BLK_CNT*(BLOCK_SIZE/8)];
	BYTE decryptOut[MAX_BLK_CNT*(BLOCK_SIZE/8)];
	BYTE iv[BLOCK_SIZE/8];
	int  i,byteCnt;

	if (makeKey(&ki,DIR_ENCRYPT,keySize,NULL) != TRUE)
		return 1;				/* 'dummy' setup for a 128-bit key */
	if (cipherInit(&ci,mode,NULL) != TRUE)
		return 1;				/* 'dummy' setup for cipher */
	
	for (i=0;i<keySize/32;i++)	/* select key bits */
		ki.key32[i]=0x10003 * rand();
	reKey(&ki);					/* run the key schedule */

	if (mode != MODE_ECB)		/* set up random iv (if needed)*/
		{
		for (i=0;i<sizeof(iv);i++)
			iv[i]=(BYTE) rand();
		memcpy(ci.iv32,iv,sizeof(ci.iv32));	/* copy the IV to ci */
		}

	/* select number of bytes to encrypt (multiple of block) */
	/* e.g., byteCnt = 16, 32, 48, 64 */
	byteCnt = (BLOCK_SIZE/8) * (1 + (rand() % MAX_BLK_CNT));

	for (i=0;i<byteCnt;i++)		/* generate test data */
		plainText[i]=(BYTE) rand();
	
	/* encrypt the bytes */
	if (blockEncrypt(&ci,&ki, plainText,byteCnt*8,cipherText) != byteCnt*8)
		return 1;

	/* decrypt the bytes */
	if (mode != MODE_ECB)		/* first re-init the IV (if needed) */
		memcpy(ci.iv32,iv,sizeof(ci.iv32));

	if (blockDecrypt(&ci,&ki,cipherText,byteCnt*8,decryptOut) != byteCnt*8)
		return 1;				
	
	/* make sure the decrypt output matches original plaintext */
	if (memcmp(plainText,decryptOut,byteCnt))
		return 1;		

	return 0;					/* tests passed! */
	}

void main(void)
	{
	int testCnt,keySize;

	srand((unsigned) time(NULL));	/* randomize */

	for (keySize=128;keySize<=256;keySize+=64)
		for (testCnt=0;testCnt<10;testCnt++)
			{
			if (TestTwofish(MODE_ECB,keySize))
				{ printf("ECB Failure at keySize=%d",keySize); return; }
			if (TestTwofish(MODE_CBC,keySize))
				{ printf("CBC Failure at keySize=%d",keySize); return; }
			}
	printf("Tests passed");
	}
#endif /* TEST_2FISH */