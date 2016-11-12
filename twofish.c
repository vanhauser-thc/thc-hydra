/***************************************************************************
	TWOFISH.C	-- C API calls for TWOFISH AES submission

	Submitters:
		Bruce Schneier, Counterpane Systems
		Doug Whiting,	Hi/fn
		John Kelsey,	Counterpane Systems
		Chris Hall,		Counterpane Systems
		David Wagner,	UC Berkeley
			
	Code Author:		Doug Whiting,	Hi/fn
		
	Version  1.00		April 1998
		
	Copyright 1998, Hi/fn and Counterpane Systems.  All rights reserved.
		
	Notes:
		*	Pedagogical version (non-optimized)
		*	Tab size is set to 4 characters in this file

***************************************************************************/

#include	"twofish/aes.h"
#include	"twofish/table.h"

/*
+*****************************************************************************
*			Constants/Macros/Tables
-****************************************************************************/

#define		VALIDATE_PARMS	1		/* nonzero --> check all parameters */
#define		FEISTEL			0		/* nonzero --> use Feistel version (slow) */

int  tabEnable=0;					/* are we gathering stats? */
BYTE tabUsed[256];					/* one bit per table */

#if FEISTEL
CONST		char *moduleDescription="Pedagogical C code (Feistel)";
#else
CONST		char *moduleDescription="Pedagogical C code";
#endif
CONST		char *modeString = "";

#define	P0_USED		0x01
#define	P1_USED		0x02
#define	B0_USED		0x04
#define	B1_USED		0x08
#define	B2_USED		0x10
#define	B3_USED		0x20
#define	ALL_USED	0x3F

/* number of rounds for various key sizes: 128, 192, 256 */
int			numRounds[4]= {0,ROUNDS_128,ROUNDS_192,ROUNDS_256};

#ifndef	DEBUG
#ifdef GetCodeSize
#define	DEBUG	1					/* force debug */
#endif
#endif
#include	"twofish/debug.h"				/* debug display macros */

#ifdef GetCodeSize
extern DWORD Here(DWORD x);			/* return caller's address! */
DWORD TwofishCodeStart(void) { return Here(0); };
#endif

/*
+*****************************************************************************
*
* Function Name:	TableOp
*
* Function:			Handle table use checking
*
* Arguments:		op	=	what to do	(see TAB_* defns in AES.H)
*
* Return:			TRUE --> done (for TAB_QUERY)		
*
* Notes: This routine is for use in generating the tables KAT file.
*
-****************************************************************************/
int TableOp(int op)
	{
	static int queryCnt=0;
	int i;
	switch (op)
		{
		case TAB_DISABLE:
			tabEnable=0;
			break;
		case TAB_ENABLE:
			tabEnable=1;
			break;
		case TAB_RESET:
			queryCnt=0;
			for (i=0;i<256;i++)
				tabUsed[i]=0;
			break;
		case TAB_QUERY:
			queryCnt++;
			for (i=0;i<256;i++)
				if (tabUsed[i] != ALL_USED)
					return FALSE;
			if (queryCnt < TAB_MIN_QUERY)	/* do a certain minimum number */
				return FALSE;
			break;
		}
	return TRUE;
	}


/*
+*****************************************************************************
*
* Function Name:	ParseHexDword
*
* Function:			Parse ASCII hex nibbles and fill in key/iv dwords
*
* Arguments:		bit			=	# bits to read
*					srcTxt		=	ASCII source
*					d			=	ptr to dwords to fill in
*					dstTxt		=	where to make a copy of ASCII source
*									(NULL ok)
*
* Return:			Zero if no error.  Nonzero --> invalid hex or length
*
* Notes:  Note that the parameter d is a DWORD array, not a byte array.
*	This routine is coded to work both for little-endian and big-endian
*	architectures.  The character stream is interpreted as a LITTLE-ENDIAN
*	byte stream, since that is how the Pentium works, but the conversion
*	happens automatically below. 
*
-****************************************************************************/
int ParseHexDword(int bits,CONST char *srcTxt,DWORD *d,char *dstTxt)
	{
	int i;
	DWORD b;
	char c;
#if ALIGN32
	char alignDummy[3];	/* keep dword alignment */
#endif

	union	/* make sure LittleEndian is defined correctly */
		{
		BYTE  b[4];
		DWORD d[1];
		} v;
	v.d[0]=1;
	if (v.b[0 ^ ADDR_XOR] != 1)	/* sanity check on compile-time switch */
		return BAD_ENDIAN;

#if VALIDATE_PARMS
  #if ALIGN32
	if (((int)d) & 3)
		return BAD_ALIGN32;
  #endif
#endif

	for (i=0;i*32<bits;i++)
		d[i]=0;					/* first, zero the field */

	for (i=0;i*4<bits;i++)		/* parse one nibble at a time */
		{						/* case out the hexadecimal characters */
		c=srcTxt[i];
		if (dstTxt) dstTxt[i]=c;
		if ((c >= '0') && (c <= '9'))
			b=c-'0';
		else if ((c >= 'a') && (c <= 'f'))
			b=c-'a'+10;
		else if ((c >= 'A') && (c <= 'F'))
			b=c-'A'+10;
		else
			return BAD_KEY_MAT;	/* invalid hex character */
		/* works for big and little endian! */
		d[i/8] |= b << (4*((i^1)&7));		
		}

	return 0;					/* no error */
	}


/*
+*****************************************************************************
*
* Function Name:	f32
*
* Function:			Run four bytes through keyed S-boxes and apply MDS matrix
*
* Arguments:		x			=	input to f function
*					k32			=	pointer to key dwords
*					keyLen		=	total key length (k32 --> keyLey/2 bits)
*
* Return:			The output of the keyed permutation applied to x.
*
* Notes:
*	This function is a keyed 32-bit permutation.  It is the major building
*	block for the Twofish round function, including the four keyed 8x8 
*	permutations and the 4x4 MDS matrix multiply.  This function is used
*	both for generating round subkeys and within the round function on the
*	block being encrypted.  
*
*	This version is fairly slow and pedagogical, although a smartcard would
*	probably perform the operation exactly this way in firmware.   For
*	ultimate performance, the entire operation can be completed with four
*	lookups into four 256x32-bit tables, with three dword xors.
*
*	The MDS matrix is defined in TABLE.H.  To multiply by Mij, just use the
*	macro Mij(x).
*
-****************************************************************************/
DWORD f32(DWORD x,CONST DWORD *k32,int keyLen)
	{
	BYTE  b[4];
	
	/* Run each byte thru 8x8 S-boxes, xoring with key byte at each stage. */
	/* Note that each byte goes through a different combination of S-boxes.*/

	*((DWORD *)b) = Bswap(x);	/* make b[0] = LSB, b[3] = MSB */
	switch (((keyLen + 63)/64) & 3)
		{
		case 0:		/* 256 bits of key */
			b[0] = p8(04)[b[0]] ^ b0(k32[3]);
			b[1] = p8(14)[b[1]] ^ b1(k32[3]);
			b[2] = p8(24)[b[2]] ^ b2(k32[3]);
			b[3] = p8(34)[b[3]] ^ b3(k32[3]);
			/* fall thru, having pre-processed b[0]..b[3] with k32[3] */
		case 3:		/* 192 bits of key */
			b[0] = p8(03)[b[0]] ^ b0(k32[2]);
			b[1] = p8(13)[b[1]] ^ b1(k32[2]);
			b[2] = p8(23)[b[2]] ^ b2(k32[2]);
			b[3] = p8(33)[b[3]] ^ b3(k32[2]);
			/* fall thru, having pre-processed b[0]..b[3] with k32[2] */
		case 2:		/* 128 bits of key */
			b[0] = p8(00)[p8(01)[p8(02)[b[0]] ^ b0(k32[1])] ^ b0(k32[0])];
			b[1] = p8(10)[p8(11)[p8(12)[b[1]] ^ b1(k32[1])] ^ b1(k32[0])];
			b[2] = p8(20)[p8(21)[p8(22)[b[2]] ^ b2(k32[1])] ^ b2(k32[0])];
			b[3] = p8(30)[p8(31)[p8(32)[b[3]] ^ b3(k32[1])] ^ b3(k32[0])];
		}

	if (tabEnable)
		{	/* we could give a "tighter" bound, but this works acceptably well */
		tabUsed[b0(x)] |= (P_00 == 0) ? P0_USED : P1_USED;
		tabUsed[b1(x)] |= (P_10 == 0) ? P0_USED : P1_USED;
		tabUsed[b2(x)] |= (P_20 == 0) ? P0_USED : P1_USED;
		tabUsed[b3(x)] |= (P_30 == 0) ? P0_USED : P1_USED;

		tabUsed[b[0] ] |= B0_USED;
		tabUsed[b[1] ] |= B1_USED;
		tabUsed[b[2] ] |= B2_USED;
		tabUsed[b[3] ] |= B3_USED;
		}

	/* Now perform the MDS matrix multiply inline. */
	return	((M00(b[0]) ^ M01(b[1]) ^ M02(b[2]) ^ M03(b[3]))	  ) ^
			((M10(b[0]) ^ M11(b[1]) ^ M12(b[2]) ^ M13(b[3])) <<  8) ^
			((M20(b[0]) ^ M21(b[1]) ^ M22(b[2]) ^ M23(b[3])) << 16) ^
			((M30(b[0]) ^ M31(b[1]) ^ M32(b[2]) ^ M33(b[3])) << 24) ;
	}

/*
+*****************************************************************************
*
* Function Name:	RS_MDS_Encode
*
* Function:			Use (12,8) Reed-Solomon code over GF(256) to produce
*					a key S-box dword from two key material dwords.
*
* Arguments:		k0	=	1st dword
*					k1	=	2nd dword
*
* Return:			Remainder polynomial generated using RS code
*
* Notes:
*	Since this computation is done only once per reKey per 64 bits of key,
*	the performance impact of this routine is imperceptible. The RS code
*	chosen has "simple" coefficients to allow smartcard/hardware implementation
*	without lookup tables.
*
-****************************************************************************/
DWORD RS_MDS_Encode(DWORD k0,DWORD k1)
	{
	int i,j;
	DWORD r;

	for (i=r=0;i<2;i++)
		{
		r ^= (i) ? k0 : k1;			/* merge in 32 more key bits */
		for (j=0;j<4;j++)			/* shift one byte at a time */
			RS_rem(r);				
		}
	return r;
	}

/*
+*****************************************************************************
*
* Function Name:	reKey
*
* Function:			Initialize the Twofish key schedule from key32
*
* Arguments:		key			=	ptr to keyInstance to be initialized
*
* Return:			TRUE on success
*
* Notes:
*	Here we precompute all the round subkeys, although that is not actually
*	required.  For example, on a smartcard, the round subkeys can 
*	be generated on-the-fly	using f32()
*
-****************************************************************************/
int reKey(keyInstance *key)
	{
	int		i,k64Cnt;
	int		keyLen	  = key->keyLen;
	int		subkeyCnt = ROUND_SUBKEYS + 2*key->numRounds;
	DWORD	A,B;
	DWORD	k32e[MAX_KEY_BITS/64],k32o[MAX_KEY_BITS/64]; /* even/odd key dwords */

#if VALIDATE_PARMS
  #if ALIGN32
	if ((((int)key) & 3) || (((int)key->key32) & 3))
		return BAD_ALIGN32;
  #endif
	if ((key->keyLen % 64) || (key->keyLen < MIN_KEY_BITS))
		return BAD_KEY_INSTANCE;
	if (subkeyCnt > TOTAL_SUBKEYS)
		return BAD_KEY_INSTANCE;
#endif

	k64Cnt=(keyLen+63)/64;		/* round up to next multiple of 64 bits */
	for (i=0;i<k64Cnt;i++)
		{						/* split into even/odd key dwords */
		k32e[i]=key->key32[2*i  ];
		k32o[i]=key->key32[2*i+1];
		/* compute S-box keys using (12,8) Reed-Solomon code over GF(256) */
		key->sboxKeys[k64Cnt-1-i]=RS_MDS_Encode(k32e[i],k32o[i]); /* reverse order */
		}

	for (i=0;i<subkeyCnt/2;i++)					/* compute round subkeys for PHT */
		{
		A = f32(i*SK_STEP        ,k32e,keyLen);	/* A uses even key dwords */
		B = f32(i*SK_STEP+SK_BUMP,k32o,keyLen);	/* B uses odd  key dwords */
		B = ROL(B,8);
		key->subKeys[2*i  ] = A+  B;			/* combine with a PHT */
		key->subKeys[2*i+1] = ROL(A+2*B,SK_ROTL);
		}

	DebugDumpKey(key);

	return TRUE;
	}
/*
+*****************************************************************************
*
* Function Name:	makeKey
*
* Function:			Initialize the Twofish key schedule
*
* Arguments:		key			=	ptr to keyInstance to be initialized
*					direction	=	DIR_ENCRYPT or DIR_DECRYPT
*					keyLen		=	# bits of key text at *keyMaterial
*					keyMaterial	=	ptr to hex ASCII chars representing key bits
*
* Return:			TRUE on success
*					else error code (e.g., BAD_KEY_DIR)
*
* Notes:
*	This parses the key bits from keyMaterial.  No crypto stuff happens here.
*	The function reKey() is called to actually build the key schedule after
*	the keyMaterial has been parsed.
*
-****************************************************************************/
int makeKey(keyInstance *key, BYTE direction, int keyLen,CONST char *keyMaterial)
	{
	int i;

#if VALIDATE_PARMS				/* first, sanity check on parameters */
	if (key == NULL)			
		return BAD_KEY_INSTANCE;/* must have a keyInstance to initialize */
	if ((direction != DIR_ENCRYPT) && (direction != DIR_DECRYPT))
		return BAD_KEY_DIR;		/* must have valid direction */
	if ((keyLen > MAX_KEY_BITS) || (keyLen < 8))	
		return BAD_KEY_MAT;		/* length must be valid */
	key->keySig = VALID_SIG;	/* show that we are initialized */
  #if ALIGN32
	if ((((int)key) & 3) || (((int)key->key32) & 3))
		return BAD_ALIGN32;
  #endif
#endif

	key->direction	= direction;	/* set our cipher direction */
	key->keyLen		= (keyLen+63) & ~63;		/* round up to multiple of 64 */
	key->numRounds	= numRounds[(keyLen-1)/64];
	for (i=0;i<MAX_KEY_BITS/32;i++)	/* zero unused bits */
		   key->key32[i]=0;
	key->keyMaterial[MAX_KEY_SIZE]=0;	/* terminate ASCII string */

	if ((keyMaterial == NULL) || (keyMaterial[0]==0))
		return TRUE;			/* allow a "dummy" call */
		
	if (ParseHexDword(keyLen,keyMaterial,key->key32,key->keyMaterial))
		return BAD_KEY_MAT;	

	return reKey(key);			/* generate round subkeys */
	}


/*
+*****************************************************************************
*
* Function Name:	cipherInit
*
* Function:			Initialize the Twofish cipher in a given mode
*
* Arguments:		cipher		=	ptr to cipherInstance to be initialized
*					mode		=	MODE_ECB, MODE_CBC, or MODE_CFB1
*					IV			=	ptr to hex ASCII test representing IV bytes
*
* Return:			TRUE on success
*					else error code (e.g., BAD_CIPHER_MODE)
*
-****************************************************************************/
int cipherInit(cipherInstance *cipher, BYTE mode,CONST char *IV)
	{
	int i;
#if VALIDATE_PARMS				/* first, sanity check on parameters */
	if (cipher == NULL)			
		return BAD_PARAMS;		/* must have a cipherInstance to initialize */
	if ((mode != MODE_ECB) && (mode != MODE_CBC) && (mode != MODE_CFB1))
		return BAD_CIPHER_MODE;	/* must have valid cipher mode */
	cipher->cipherSig	=	VALID_SIG;
  #if ALIGN32
	if ((((int)cipher) & 3) || (((int)cipher->IV) & 3) || (((int)cipher->iv32) & 3))
		return BAD_ALIGN32;
  #endif
#endif

	if ((mode != MODE_ECB) && (IV))	/* parse the IV */
		{
		if (ParseHexDword(BLOCK_SIZE,IV,cipher->iv32,NULL))
			return BAD_IV_MAT;
		for (i=0;i<BLOCK_SIZE/32;i++)	/* make byte-oriented copy for CFB1 */
			((DWORD *)cipher->IV)[i] = Bswap(cipher->iv32[i]);
		}

	cipher->mode		=	mode;

	return TRUE;
	}

/*
+*****************************************************************************
*
* Function Name:	blockEncrypt
*
* Function:			Encrypt block(s) of data using Twofish
*
* Arguments:		cipher		=	ptr to already initialized cipherInstance
*					key			=	ptr to already initialized keyInstance
*					input		=	ptr to data blocks to be encrypted
*					inputLen	=	# bits to encrypt (multiple of blockSize)
*					outBuffer	=	ptr to where to put encrypted blocks
*
* Return:			# bits ciphered (>= 0)
*					else error code (e.g., BAD_CIPHER_STATE, BAD_KEY_MATERIAL)
*
* Notes: The only supported block size for ECB/CBC modes is BLOCK_SIZE bits.
*		 If inputLen is not a multiple of BLOCK_SIZE bits in those modes,
*		 an error BAD_INPUT_LEN is returned.  In CFB1 mode, all block 
*		 sizes can be supported.
*
-****************************************************************************/
int blockEncrypt(cipherInstance *cipher, keyInstance *key,CONST BYTE *input,
				int inputLen, BYTE *outBuffer)
	{
	int   i,n,r;					/* loop variables */
	DWORD x[BLOCK_SIZE/32];			/* block being encrypted */
	DWORD t0,t1,tmp;				/* temp variables */
	int	  rounds=key->numRounds;	/* number of rounds */
	BYTE  bit,ctBit,carry;			/* temps for CFB */
#if ALIGN32
	BYTE alignDummy;				/* keep 32-bit variable alignment on stack */
#endif

#if VALIDATE_PARMS
	if ((cipher == NULL) || (cipher->cipherSig != VALID_SIG))
		return BAD_CIPHER_STATE;
	if ((key == NULL) || (key->keySig != VALID_SIG))
		return BAD_KEY_INSTANCE;
	if ((rounds < 2) || (rounds > MAX_ROUNDS) || (rounds&1))
		return BAD_KEY_INSTANCE;
	if ((cipher->mode != MODE_CFB1) && (inputLen % BLOCK_SIZE))
		return BAD_INPUT_LEN;
  #if ALIGN32
	if ( (((int)cipher) & 3) || (((int)key      ) & 3) ||
		 (((int)input ) & 3) || (((int)outBuffer) & 3))
		return BAD_ALIGN32;
  #endif
#endif

	if (cipher->mode == MODE_CFB1)
		{	/* use recursion here to handle CFB, one block at a time */
		cipher->mode = MODE_ECB;	/* do encryption in ECB */
		for (n=0;n<inputLen;n++)
			{
			blockEncrypt(cipher,key,cipher->IV,BLOCK_SIZE,(BYTE *)x);
			bit	  = 0x80 >> (n & 7);/* which bit position in byte */
			ctBit = (input[n/8] & bit) ^ ((((BYTE *) x)[0] & 0x80) >> (n&7));
			outBuffer[n/8] = (outBuffer[n/8] & ~ bit) | ctBit;
			carry = ctBit >> (7 - (n&7));
			for (i=BLOCK_SIZE/8-1;i>=0;i--)
				{
				bit = cipher->IV[i] >> 7;	/* save next "carry" from shift */
				cipher->IV[i] = (cipher->IV[i] << 1) ^ carry;
				carry = bit;
				}
			}
		cipher->mode = MODE_CFB1;	/* restore mode for next time */
		return inputLen;
		}

	/* here for ECB, CBC modes */
	for (n=0;n<inputLen;n+=BLOCK_SIZE,input+=BLOCK_SIZE/8,outBuffer+=BLOCK_SIZE/8)
		{
#ifdef DEBUG
		DebugDump(input,"\n",-1,0,0,0,1);
		if (cipher->mode == MODE_CBC)
			DebugDump(cipher->iv32,"",IV_ROUND,0,0,0,0);
#endif
		for (i=0;i<BLOCK_SIZE/32;i++)	/* copy in the block, add whitening */
			{
			x[i]=Bswap(((DWORD *)input)[i]) ^ key->subKeys[INPUT_WHITEN+i];
			if (cipher->mode == MODE_CBC)
				x[i] ^= Bswap(cipher->iv32[i]);
			}

		DebugDump(x,"",0,0,0,0,0);
		for (r=0;r<rounds;r++)			/* main Twofish encryption loop */
			{	
#if FEISTEL
			t0	 = f32(ROR(x[0],  (r+1)/2),key->sboxKeys,key->keyLen);
			t1	 = f32(ROL(x[1],8+(r+1)/2),key->sboxKeys,key->keyLen);
										/* PHT, round keys */
			x[2]^= ROL(t0 +   t1 + key->subKeys[ROUND_SUBKEYS+2*r  ], r    /2);
			x[3]^= ROR(t0 + 2*t1 + key->subKeys[ROUND_SUBKEYS+2*r+1],(r+2) /2);

			DebugDump(x,"",r+1,2*(r&1),1,1,0);
#else
			t0	 = f32(    x[0]   ,key->sboxKeys,key->keyLen);
			t1	 = f32(ROL(x[1],8),key->sboxKeys,key->keyLen);

			x[3] = ROL(x[3],1);
			x[2]^= t0 +   t1 + key->subKeys[ROUND_SUBKEYS+2*r  ]; /* PHT, round keys */
			x[3]^= t0 + 2*t1 + key->subKeys[ROUND_SUBKEYS+2*r+1];
			x[2] = ROR(x[2],1);

			DebugDump(x,"",r+1,2*(r&1),0,1,0);/* make format compatible with optimized code */
#endif
			if (r < rounds-1)						/* swap for next round */
				{
				tmp = x[0]; x[0]= x[2]; x[2] = tmp;
				tmp = x[1]; x[1]= x[3]; x[3] = tmp;
				}
			}
#if FEISTEL
		x[0] = ROR(x[0],8);                     /* "final permutation" */
		x[1] = ROL(x[1],8);
		x[2] = ROR(x[2],8);
		x[3] = ROL(x[3],8);
#endif
		for (i=0;i<BLOCK_SIZE/32;i++)	/* copy out, with whitening */
			{
			((DWORD *)outBuffer)[i] = Bswap(x[i] ^ key->subKeys[OUTPUT_WHITEN+i]);
			if (cipher->mode == MODE_CBC)
				cipher->iv32[i] = ((DWORD *)outBuffer)[i];
			}
#ifdef DEBUG
		DebugDump(outBuffer,"",rounds+1,0,0,0,1);
		if (cipher->mode == MODE_CBC)
			DebugDump(cipher->iv32,"",IV_ROUND,0,0,0,0);
#endif
		}

	return inputLen;
	}

/*
+*****************************************************************************
*
* Function Name:	blockDecrypt
*
* Function:			Decrypt block(s) of data using Twofish
*
* Arguments:		cipher		=	ptr to already initialized cipherInstance
*					key			=	ptr to already initialized keyInstance
*					input		=	ptr to data blocks to be decrypted
*					inputLen	=	# bits to encrypt (multiple of blockSize)
*					outBuffer	=	ptr to where to put decrypted blocks
*
* Return:			# bits ciphered (>= 0)
*					else error code (e.g., BAD_CIPHER_STATE, BAD_KEY_MATERIAL)
*
* Notes: The only supported block size for ECB/CBC modes is BLOCK_SIZE bits.
*		 If inputLen is not a multiple of BLOCK_SIZE bits in those modes,
*		 an error BAD_INPUT_LEN is returned.  In CFB1 mode, all block 
*		 sizes can be supported.
*
-****************************************************************************/
int blockDecrypt(cipherInstance *cipher, keyInstance *key,CONST BYTE *input,
				int inputLen, BYTE *outBuffer)
	{
	int   i,n,r;					/* loop counters */
	DWORD x[BLOCK_SIZE/32];			/* block being encrypted */
	DWORD t0,t1;					/* temp variables */
	int	  rounds=key->numRounds;	/* number of rounds */
	BYTE  bit,ctBit,carry;			/* temps for CFB */
#if ALIGN32
	BYTE alignDummy;				/* keep 32-bit variable alignment on stack */
#endif

#if VALIDATE_PARMS
	if ((cipher == NULL) || (cipher->cipherSig != VALID_SIG))
		return BAD_CIPHER_STATE;
	if ((key == NULL) || (key->keySig != VALID_SIG))
		return BAD_KEY_INSTANCE;
	if ((rounds < 2) || (rounds > MAX_ROUNDS) || (rounds&1))
		return BAD_KEY_INSTANCE;
	if ((cipher->mode != MODE_CFB1) && (inputLen % BLOCK_SIZE))
		return BAD_INPUT_LEN;
  #if ALIGN32
	if ( (((int)cipher) & 3) || (((int)key      ) & 3) ||
		 (((int)input)  & 3) || (((int)outBuffer) & 3))
		return BAD_ALIGN32;
  #endif
#endif

	if (cipher->mode == MODE_CFB1)
		{	/* use blockEncrypt here to handle CFB, one block at a time */
		cipher->mode = MODE_ECB;	/* do encryption in ECB */
		for (n=0;n<inputLen;n++)
			{
			blockEncrypt(cipher,key,cipher->IV,BLOCK_SIZE,(BYTE *)x);
			bit	  = 0x80 >> (n & 7);
			ctBit = input[n/8] & bit;
			outBuffer[n/8] = (outBuffer[n/8] & ~ bit) |
							 (ctBit ^ ((((BYTE *) x)[0] & 0x80) >> (n&7)));
			carry = ctBit >> (7 - (n&7));
			for (i=BLOCK_SIZE/8-1;i>=0;i--)
				{
				bit = cipher->IV[i] >> 7;	/* save next "carry" from shift */
				cipher->IV[i] = (cipher->IV[i] << 1) ^ carry;
				carry = bit;
				}
			}
		cipher->mode = MODE_CFB1;	/* restore mode for next time */
		return inputLen;
		}

	/* here for ECB, CBC modes */
	for (n=0;n<inputLen;n+=BLOCK_SIZE,input+=BLOCK_SIZE/8,outBuffer+=BLOCK_SIZE/8)
		{
		DebugDump(input,"\n",rounds+1,0,0,0,1);

		for (i=0;i<BLOCK_SIZE/32;i++)	/* copy in the block, add whitening */
			x[i]=Bswap(((DWORD *)input)[i]) ^ key->subKeys[OUTPUT_WHITEN+i];

		for (r=rounds-1;r>=0;r--)			/* main Twofish decryption loop */
			{
			t0	 = f32(    x[0]   ,key->sboxKeys,key->keyLen);
			t1	 = f32(ROL(x[1],8),key->sboxKeys,key->keyLen);

			DebugDump(x,"",r+1,2*(r&1),0,1,0);/* make format compatible with optimized code */
			x[2] = ROL(x[2],1);
			x[2]^= t0 +   t1 + key->subKeys[ROUND_SUBKEYS+2*r  ]; /* PHT, round keys */
			x[3]^= t0 + 2*t1 + key->subKeys[ROUND_SUBKEYS+2*r+1];
			x[3] = ROR(x[3],1);

			if (r)									/* unswap, except for last round */
				{
				t0   = x[0]; x[0]= x[2]; x[2] = t0;	
				t1   = x[1]; x[1]= x[3]; x[3] = t1;
				}
			}
		DebugDump(x,"",0,0,0,0,0);/* make final output match encrypt initial output */

		for (i=0;i<BLOCK_SIZE/32;i++)	/* copy out, with whitening */
			{
			x[i] ^= key->subKeys[INPUT_WHITEN+i];
			if (cipher->mode == MODE_CBC)
				{
				x[i] ^= Bswap(cipher->iv32[i]);
				cipher->iv32[i] = ((DWORD *)input)[i];
				}
			((DWORD *)outBuffer)[i] = Bswap(x[i]);
			}
		DebugDump(outBuffer,"",-1,0,0,0,1);
		}

	return inputLen;
	}


#ifdef GetCodeSize
DWORD TwofishCodeSize(void) { return Here(0)-TwofishCodeStart(); };
#endif
