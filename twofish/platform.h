/***************************************************************************
	PLATFORM.H	-- Platform-specific defines for TWOFISH code

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
		*	Tab size is set to 4 characters in this file

***************************************************************************/

/* use intrinsic rotate if possible */
#define	ROL(x,n) (((x) << ((n) & 0x1F)) | ((x) >> (32-((n) & 0x1F))))
#define	ROR(x,n) (((x) >> ((n) & 0x1F)) | ((x) << (32-((n) & 0x1F))))

#if (0) && defined(__BORLANDC__) && (__BORLANDC__ >= 0x462)
#error "!!!This does not work for some reason!!!"
#include	<stdlib.h>					/* get prototype for _lrotl() , _lrotr() */
#pragma inline __lrotl__
#pragma inline __lrotr__
#undef	ROL								/* get rid of inefficient definitions */
#undef	ROR
#define	ROL(x,n)	__lrotl__(x,n)		/* use compiler intrinsic rotations */
#define	ROR(x,n)	__lrotr__(x,n)
#endif

#ifdef _MSC_VER
#include	<stdlib.h>					/* get prototypes for rotation functions */
#undef	ROL
#undef	ROR
#pragma intrinsic(_lrotl,_lrotr)		/* use intrinsic compiler rotations */
#define	ROL(x,n)	_lrotl(x,n)			
#define	ROR(x,n)	_lrotr(x,n)
#endif

#if !defined(__i386__) && !defined(__x86_64__)
#ifdef	__BORLANDC__
#define	__i386__				300		/* make sure this is defined for Intel CPUs */
#endif
#endif

#if defined(__i386__) || defined(__x86_64__) || defined(__arm__)
#define		LittleEndian		1		/* e.g., 1 for Pentium, 0 for 68K */
#define		ALIGN32				0		/* need dword alignment? (no for Pentium) */
#else	/* non-Intel platforms */
#define		LittleEndian		0		/* (assume big endian */
#define		ALIGN32				0		/* (assume need alignment for non-Intel) */
#endif

#if LittleEndian
#define		Bswap(x)			(x)		/* NOP for little-endian machines */
#define		ADDR_XOR			0		/* NOP for little-endian machines */
#else
#define		Bswap(x)			((ROR(x,8) & 0xFF00FF00) | (ROL(x,8) & 0x00FF00FF))
#define		ADDR_XOR			3		/* convert byte address in dword */
#endif

/*	Macros for extracting bytes from dwords (correct for endianness) */
#define	_b(x,N)	(((BYTE *)&x)[((N) & 3) ^ ADDR_XOR]) /* pick bytes out of a dword */

#define		b0(x)			_b(x,0)		/* extract LSB of DWORD */
#define		b1(x)			_b(x,1)
#define		b2(x)			_b(x,2)
#define		b3(x)			_b(x,3)		/* extract MSB of DWORD */

