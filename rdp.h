/*
   david: this file is based on header files from rdesktop project

   rdesktop: A Remote Desktop Protocol client.
   Master include file
   Copyright (C) Matthew Chapman 1999-2008

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "hydra-mod.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#define WINVER 0x0400
#include <windows.h>
#include <winsock.h>
#include <time.h>
#define DIR int
#else
#include <dirent.h>
#include <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif
#endif
#include <limits.h>		/* PATH_MAX */
#ifdef HAVE_SYSEXITS_H
#include <sysexits.h>
#endif

#include <sys/stat.h>           /* stat */
#include <sys/time.h>           /* gettimeofday */
#include <sys/times.h>          /* times */

//fixme

/* The system could not log you on. Make sure your User name and domain are correct [FAILED] */
#define LOGON_MESSAGE_FAILED_XP  "\x00\x00\x01\x06\x02\x06\x04\x09\x05\x05\x04\x06\x06\x05\x02\x04\x07\x06"
#define LOGON_MESSAGE_FAILED_2K3 "\x00\x00\x01\x08\x02\x07\x03\x07\x04\x07\x05\x05\x01\x05\x04\x07\x03\x05"
#define LOGON_MESSAGE_FAILED_2K8 "not needed"

#define LOGON_MESSAGE_2K "\x00\x00\x01\x06\x02\x07\x04\x0a\x05\x08\x06\x0a\x01\x05\x07\x0a\x08\x0b\x05\x03\x09\x07\x01\x07\x0a\x07\x0b\x09\xff\x00\x1c"

/* The local policy of this system does not permit you to logon interactively. [SUCCESS] */
#define LOGON_MESSAGE_NO_INTERACTIVE_XP "\x00\x00\x01\x06\x02\x06\x04\x09\x05\x02\x06\x06\x07\x05\x04\x06\x08\x05"
#define LOGON_MESSAGE_NO_INTERACTIVE_2K3 "??"

/* Unable to log you on because your account has been locked out [FAILED] */
#define LOGON_MESSAGE_LOCKED_XP  "\x00\x00\x01\x07\x02\x06\x03\x06\x04\x06\x05\x02\x07\x09\x08\x04\x04\x09"
#define LOGON_MESSAGE_LOCKED_2K3 "??"

/* Your account has been disabled. Please see your system administrator. [ERROR] */
/* Your account has expired. Please see your system administrator. [ERROR] */
#define LOGON_MESSAGE_DISABLED_XP  "\x00\x00\x01\x06\x02\x06\x03\x06\x05\x07\x06\x06\x06\x05\x01\x05\x02\x06"
#define LOGON_MESSAGE_DISABLED_2K3 "??"

/* Your password has expired and must be changed. [SUCCESS] */
#define LOGON_MESSAGE_EXPIRED_XP  "\x00\x00\x01\x06\x02\x06\x03\x06\x05\x07\x06\x06\x07\x06\x07\x05\x08\x05"
#define LOGON_MESSAGE_EXPIRED_2K3 "??"

/* You are required to change your password at first logon. [SUCCESS] */
#define LOGON_MESSAGE_MUST_CHANGE_XP  "\x00\x00\x01\x06\x02\x06\x04\x09\x05\x06\x06\x04\x05\x09\x06\x04\x07\x06"
#define LOGON_MESSAGE_MUST_CHANGE_2K3 "??"

/* The terminal server has exceeded the maximum number of allowed connections. [SUCCESS] */
#define LOGON_MESSAGE_MSTS_MAX_2K3 "\x00\x00\x01\x06\x02\x07\x01\x07\x05\x07\x24\x0a\x25\x0a\x0b\x07\x0b\x06\x26"


#define DEBUG(args)	{ if (debug) {hydra_report(stderr, "[DEBUG] "); printf args; }}
#define DEBUG_RDP5(args){ if (debug) {hydra_report(stderr, "[DEBUG] RDP5 "); printf args; }}

#define STRNCPY(dst,src,n)	{ strncpy(dst,src,n-1); dst[n-1] = 0; }

#ifndef MIN
#define MIN(x,y)		(((x) < (y)) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x,y)		(((x) > (y)) ? (x) : (y))
#endif

/* timeval macros */
#ifndef timerisset
#define timerisset(tvp)\
         ((tvp)->tv_sec || (tvp)->tv_usec)
#endif
#ifndef timercmp
#define timercmp(tvp, uvp, cmp)\
        ((tvp)->tv_sec cmp (uvp)->tv_sec ||\
        (tvp)->tv_sec == (uvp)->tv_sec &&\
        (tvp)->tv_usec cmp (uvp)->tv_usec)
#endif
#ifndef timerclear
#define timerclear(tvp)\
        ((tvp)->tv_sec = (tvp)->tv_usec = 0)
#endif

/* If configure does not define the endianess, try
   to find it out */
#if !defined(L_ENDIAN) && !defined(B_ENDIAN)
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define L_ENDIAN
#elif __BYTE_ORDER == __BIG_ENDIAN
#define B_ENDIAN
#else
#error Unknown endianness. Edit rdp.h.
#endif
#endif /* B_ENDIAN, L_ENDIAN from configure */

/* No need for alignment on x86 and amd64 */
#if !defined(NEED_ALIGN)
#if !(defined(__x86__) || defined(__x86_64__) || \
      defined(__AMD64__) || defined(_M_IX86) || \
      defined(__i386__))
#define NEED_ALIGN
#endif
#endif

/* Parser state */
typedef struct stream
{
	unsigned char *p;
	unsigned char *end;
	unsigned char *data;
	unsigned int size;

	/* Offsets of various headers */
	unsigned char *iso_hdr;
	unsigned char *mcs_hdr;
	unsigned char *sec_hdr;
	unsigned char *rdp_hdr;
	unsigned char *channel_hdr;

}
 *STREAM;

#define s_push_layer(s,h,n)	{ (s)->h = (s)->p; (s)->p += n; }
#define s_pop_layer(s,h)	(s)->p = (s)->h;
#define s_mark_end(s)		(s)->end = (s)->p;
#define s_check(s)		((s)->p <= (s)->end)
#define s_check_rem(s,n)	((s)->p + n <= (s)->end)
#define s_check_end(s)		((s)->p == (s)->end)

#if defined(L_ENDIAN) && !defined(NEED_ALIGN)
#define in_uint16_le(s,v)	{ v = *(uint16 *)((s)->p); (s)->p += 2; }
#define in_uint32_le(s,v)	{ v = *(uint32 *)((s)->p); (s)->p += 4; }
#define out_uint16_le(s,v)	{ *(uint16 *)((s)->p) = v; (s)->p += 2; }
#define out_uint32_le(s,v)	{ *(uint32 *)((s)->p) = v; (s)->p += 4; }

#else
#define in_uint16_le(s,v)	{ v = *((s)->p++); v += *((s)->p++) << 8; }
#define in_uint32_le(s,v)	{ in_uint16_le(s,v) \
				v += *((s)->p++) << 16; v += *((s)->p++) << 24; }
#define out_uint16_le(s,v)	{ *((s)->p++) = (v) & 0xff; *((s)->p++) = ((v) >> 8) & 0xff; }
#define out_uint32_le(s,v)	{ out_uint16_le(s, (v) & 0xffff); out_uint16_le(s, ((v) >> 16) & 0xffff); }
#endif

#if defined(B_ENDIAN) && !defined(NEED_ALIGN)
#define in_uint16_be(s,v)	{ v = *(uint16 *)((s)->p); (s)->p += 2; }
#define in_uint32_be(s,v)	{ v = *(uint32 *)((s)->p); (s)->p += 4; }
#define out_uint16_be(s,v)	{ *(uint16 *)((s)->p) = v; (s)->p += 2; }
#define out_uint32_be(s,v)	{ *(uint32 *)((s)->p) = v; (s)->p += 4; }

#define B_ENDIAN_PREFERRED
#define in_uint16(s,v)		in_uint16_be(s,v)
#define in_uint32(s,v)		in_uint32_be(s,v)
#define out_uint16(s,v)		out_uint16_be(s,v)
#define out_uint32(s,v)		out_uint32_be(s,v)

#else
#define in_uint16_be(s,v)	{ v = *((s)->p++); next_be(s,v); }
#define in_uint32_be(s,v)	{ in_uint16_be(s,v); next_be(s,v); next_be(s,v); }
#define out_uint16_be(s,v)	{ *((s)->p++) = ((v) >> 8) & 0xff; *((s)->p++) = (v) & 0xff; }
#define out_uint32_be(s,v)	{ out_uint16_be(s, ((v) >> 16) & 0xffff); out_uint16_be(s, (v) & 0xffff); }
#endif

#ifndef B_ENDIAN_PREFERRED
#define in_uint16(s,v)		in_uint16_le(s,v)
#define in_uint32(s,v)		in_uint32_le(s,v)
#define out_uint16(s,v)		out_uint16_le(s,v)
#define out_uint32(s,v)		out_uint32_le(s,v)
#endif

#define in_uint8(s,v)		v = *((s)->p++);
#define in_uint8p(s,v,n)	{ v = (s)->p; (s)->p += n; }
#define in_uint8a(s,v,n)	{ memcpy(v,(s)->p,n); (s)->p += n; }
#define in_uint8s(s,n)		(s)->p += n;
#define out_uint8(s,v)		*((s)->p++) = v;
#define out_uint8p(s,v,n)	{ memcpy((s)->p,v,n); (s)->p += n; }
#define out_uint8a(s,v,n)	out_uint8p(s,v,n);
#define out_uint8s(s,n)		{ memset((s)->p,0,n); (s)->p += n; }

#define next_be(s,v)		v = ((v) << 8) + *((s)->p++);

typedef unsigned char uint8;
typedef signed char sint8;
typedef unsigned short uint16;
typedef signed short sint16;
typedef unsigned int uint32;
typedef signed int sint32;

typedef struct _BOUNDS
{
	sint16 left;
	sint16 top;
	sint16 right;
	sint16 bottom;

}
BOUNDS;

/* PSTCACHE */
typedef uint8 HASH_KEY[8];

#ifndef PATH_MAX
#define PATH_MAX 256
#endif

#define RDP_ORDER_STANDARD   0x01
#define RDP_ORDER_SECONDARY  0x02
#define RDP_ORDER_BOUNDS     0x04
#define RDP_ORDER_CHANGE     0x08
#define RDP_ORDER_DELTA      0x10
#define RDP_ORDER_LASTBOUNDS 0x20
#define RDP_ORDER_SMALL      0x40
#define RDP_ORDER_TINY       0x80

enum RDP_ORDER_TYPE
{
	RDP_ORDER_DESTBLT = 0,
	RDP_ORDER_PATBLT = 1,
	RDP_ORDER_SCREENBLT = 2,
	RDP_ORDER_LINE = 9,
	RDP_ORDER_RECT = 10,
	RDP_ORDER_DESKSAVE = 11,
	RDP_ORDER_MEMBLT = 13,
	RDP_ORDER_TRIBLT = 14,
	RDP_ORDER_POLYGON = 20,
	RDP_ORDER_POLYGON2 = 21,
	RDP_ORDER_POLYLINE = 22,
	RDP_ORDER_ELLIPSE = 25,
	RDP_ORDER_ELLIPSE2 = 26,
	RDP_ORDER_TEXT2 = 27
};

enum RDP_SECONDARY_ORDER_TYPE
{
	RDP_ORDER_RAW_BMPCACHE = 0,
	RDP_ORDER_COLCACHE = 1,
	RDP_ORDER_BMPCACHE = 2,
	RDP_ORDER_FONTCACHE = 3,
	RDP_ORDER_RAW_BMPCACHE2 = 4,
	RDP_ORDER_BMPCACHE2 = 5,
	RDP_ORDER_BRUSHCACHE = 7
};

typedef struct _RECT_ORDER
{
	sint16 x;
	sint16 y;
	sint16 cx;
	sint16 cy;
	uint32 colour;

}
RECT_ORDER;

typedef struct _DESKSAVE_ORDER
{
	uint32 offset;
	sint16 left;
	sint16 top;
	sint16 right;
	sint16 bottom;
	uint8 action;

}
DESKSAVE_ORDER;

typedef struct _MEMBLT_ORDER
{
	uint8 colour_table;
	uint8 cache_id;
	sint16 x;
	sint16 y;
	sint16 cx;
	sint16 cy;
	uint8 opcode;
	sint16 srcx;
	sint16 srcy;
	uint16 cache_idx;

}
MEMBLT_ORDER;

#define MAX_DATA 256
#define MAX_TEXT 256

typedef struct _TEXT2_ORDER
{
	uint8 font;
	uint8 flags;
	uint8 opcode;
	uint8 mixmode;
	uint32 bgcolour;
	uint32 fgcolour;
	sint16 clipleft;
	sint16 cliptop;
	sint16 clipright;
	sint16 clipbottom;
	sint16 boxleft;
	sint16 boxtop;
	sint16 boxright;
	sint16 boxbottom;
	sint16 x;
	sint16 y;
	uint8 length;
	uint8 text[MAX_TEXT];

}
TEXT2_ORDER;

typedef struct _RDP_ORDER_STATE
{
	uint8 order_type;
	BOUNDS bounds;

	RECT_ORDER rect;
	DESKSAVE_ORDER desksave;
	MEMBLT_ORDER memblt;
	TEXT2_ORDER text2;
}
RDP_ORDER_STATE;

#define WINDOWS_CODEPAGE	"UTF-16LE"

/* ISO PDU codes */
enum ISO_PDU_CODE
{
	ISO_PDU_CR = 0xE0,	/* Connection Request */
	ISO_PDU_CC = 0xD0,	/* Connection Confirm */
	ISO_PDU_DR = 0x80,	/* Disconnect Request */
	ISO_PDU_DT = 0xF0,	/* Data */
	ISO_PDU_ER = 0x70	/* Error */
};

/* MCS PDU codes */
enum MCS_PDU_TYPE
{
	MCS_EDRQ = 1,		/* Erect Domain Request */
	MCS_DPUM = 8,		/* Disconnect Provider Ultimatum */
	MCS_AURQ = 10,		/* Attach User Request */
	MCS_AUCF = 11,		/* Attach User Confirm */
	MCS_CJRQ = 14,		/* Channel Join Request */
	MCS_CJCF = 15,		/* Channel Join Confirm */
	MCS_SDRQ = 25,		/* Send Data Request */
	MCS_SDIN = 26		/* Send Data Indication */
};

#define MCS_CONNECT_INITIAL	0x7f65
#define MCS_CONNECT_RESPONSE	0x7f66

#define BER_TAG_BOOLEAN		1
#define BER_TAG_INTEGER		2
#define BER_TAG_OCTET_STRING	4
#define BER_TAG_RESULT		10
#define MCS_TAG_DOMAIN_PARAMS	0x30

#define MCS_GLOBAL_CHANNEL	1003
#define MCS_USERCHANNEL_BASE    1001

/* RDP secure transport constants */
#define SEC_RANDOM_SIZE		32
#define SEC_MODULUS_SIZE	64
#define SEC_MAX_MODULUS_SIZE	256
#define SEC_PADDING_SIZE	8
#define SEC_EXPONENT_SIZE	4

#define SEC_CLIENT_RANDOM	0x0001
#define SEC_ENCRYPT		0x0008
#define SEC_LOGON_INFO		0x0040
#define SEC_LICENCE_NEG		0x0080
#define SEC_REDIRECT_ENCRYPT	0x0C00

#define SEC_TAG_SRV_INFO	0x0c01
#define SEC_TAG_SRV_CRYPT	0x0c02
#define SEC_TAG_SRV_CHANNELS	0x0c03

#define SEC_TAG_CLI_INFO	0xc001
#define SEC_TAG_CLI_CRYPT	0xc002
#define SEC_TAG_CLI_CHANNELS    0xc003
#define SEC_TAG_CLI_4           0xc004

#define SEC_TAG_PUBKEY		0x0006
#define SEC_TAG_KEYSIG		0x0008

#define SEC_RSA_MAGIC		0x31415352	/* RSA1 */

/* RDP PDU codes */
enum RDP_PDU_TYPE
{
	RDP_PDU_DEMAND_ACTIVE = 1,
	RDP_PDU_CONFIRM_ACTIVE = 3,
	RDP_PDU_REDIRECT = 4,	/* MS Server 2003 Session Redirect */
	RDP_PDU_DEACTIVATE = 6,
	RDP_PDU_DATA = 7
};

enum RDP_DATA_PDU_TYPE
{
	RDP_DATA_PDU_UPDATE = 2,
	RDP_DATA_PDU_CONTROL = 20,
	RDP_DATA_PDU_POINTER = 27,
	RDP_DATA_PDU_INPUT = 28,
	RDP_DATA_PDU_SYNCHRONISE = 31,
	RDP_DATA_PDU_BELL = 34,
	RDP_DATA_PDU_CLIENT_WINDOW_STATUS = 35,
	RDP_DATA_PDU_LOGON = 38,	/* PDUTYPE2_SAVE_SESSION_INFO */
	RDP_DATA_PDU_FONT2 = 39,
	RDP_DATA_PDU_KEYBOARD_INDICATORS = 41,
	RDP_DATA_PDU_DISCONNECT = 47
};

enum RDP_SAVE_SESSION_PDU_TYPE
{
	INFOTYPE_LOGON = 0,
	INFOTYPE_LOGON_LONG = 1,
	INFOTYPE_LOGON_PLAINNOTIFY = 2,
	INFOTYPE_LOGON_EXTENDED_INF = 3
};

enum RDP_LOGON_INFO_EXTENDED_TYPE
{
	LOGON_EX_AUTORECONNECTCOOKIE = 1,
	LOGON_EX_LOGONERRORS = 2
};

enum RDP_CONTROL_PDU_TYPE
{
	RDP_CTL_REQUEST_CONTROL = 1,
	RDP_CTL_GRANT_CONTROL = 2,
	RDP_CTL_DETACH = 3,
	RDP_CTL_COOPERATE = 4
};

enum RDP_UPDATE_PDU_TYPE
{
	RDP_UPDATE_ORDERS = 0,
	RDP_UPDATE_BITMAP = 1,
	RDP_UPDATE_PALETTE = 2,
	RDP_UPDATE_SYNCHRONIZE = 3
};

/* RDP bitmap cache (version 2) constants */
#define BMPCACHE2_C0_CELLS	0x78
#define BMPCACHE2_C1_CELLS	0x78
#define BMPCACHE2_C2_CELLS	0x150
#define BMPCACHE2_NUM_PSTCELLS	0x9f6

#define PDU_FLAG_FIRST		0x01
#define PDU_FLAG_LAST		0x02

/* RDP capabilities */
#define RDP_CAPSET_GENERAL	1	/* Maps to generalCapabilitySet in T.128 page 138 */
#define RDP_CAPLEN_GENERAL	0x18
#define OS_MAJOR_TYPE_UNIX	4
#define OS_MINOR_TYPE_XSERVER	7

#define RDP_CAPSET_BITMAP	2
#define RDP_CAPLEN_BITMAP	0x1C

#define RDP_CAPSET_ORDER	3
#define RDP_CAPLEN_ORDER	0x58

#define RDP_CAPSET_BMPCACHE	4
#define RDP_CAPLEN_BMPCACHE	0x28

#define RDP_CAPSET_CONTROL	5
#define RDP_CAPLEN_CONTROL	0x0C

#define RDP_CAPSET_ACTIVATE	7
#define RDP_CAPLEN_ACTIVATE	0x0C

#define RDP_CAPSET_POINTER	8
#define RDP_CAPLEN_POINTER	0x08
#define RDP_CAPLEN_NEWPOINTER	0x0a

#define RDP_CAPSET_SHARE	9
#define RDP_CAPLEN_SHARE	0x08

#define RDP_CAPSET_COLCACHE	10
#define RDP_CAPLEN_COLCACHE	0x08

#define RDP_CAPSET_BRUSHCACHE	15
#define RDP_CAPLEN_BRUSHCACHE	0x08

#define RDP_CAPSET_BMPCACHE2	19
#define RDP_CAPLEN_BMPCACHE2	0x28

#define RDP_SOURCE		"MSTSC"

/* Logon flags */
#define RDP_LOGON_AUTO		0x0008
#define RDP_LOGON_NORMAL	0x0033
#define RDP_LOGON_COMPRESSION	0x0080	/* mppc compression with 8kB histroy buffer */
#define RDP_LOGON_BLOB		0x0100
#define RDP_LOGON_COMPRESSION2	0x0200	/* rdp5 mppc compression with 64kB history buffer */
#define RDP_LOGON_LEAVE_AUDIO	0x2000

#define RDP5_DISABLE_NOTHING	0x00
#define RDP5_NO_WALLPAPER	0x01
#define RDP5_NO_FULLWINDOWDRAG	0x02
#define RDP5_NO_MENUANIMATIONS	0x04
#define RDP5_NO_THEMING		0x08
#define RDP5_NO_CURSOR_SHADOW	0x20
#define RDP5_NO_CURSORSETTINGS	0x40	/* disables cursor blinking */

/* compression types */
#define RDP_MPPC_BIG		0x01
#define RDP_MPPC_COMPRESSED	0x20
#define RDP_MPPC_RESET		0x40
#define RDP_MPPC_FLUSH		0x80
#define RDP_MPPC_DICT_SIZE      65536

#define RDP5_COMPRESSED		0x80

#ifndef _SSL_H
#define _SSL_H

#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x0090800f)
#define D2I_X509_CONST const
#else
#define D2I_X509_CONST
#endif

#define SSL_RC4 RC4_KEY
#define SSL_SHA1 SHA_CTX
#define SSL_MD5 MD5_CTX
#define SSL_CERT X509
#define SSL_RKEY RSA
#endif

/* for win8 */
#define KBD_FLAG_DOWN           0x4000
#define KBD_FLAG_UP             0x8000
#define RDP_KEYRELEASE (KBD_FLAG_DOWN | KBD_FLAG_UP)
#define FASTPATH_INPUT_KBDFLAGS_RELEASE 1
#define FASTPATH_INPUT_EVENT_SCANCODE 0
#define FASTPATH_INPUT_EVENT_MOUSE 1
#define RDP_INPUT_MOUSE 0x8001
#define RDP_INPUT_SCANCODE 4

/* iso.c */
STREAM iso_init(int length);
void iso_send(STREAM s);
STREAM iso_recv(uint8 * rdpver);
BOOL iso_connect(char *server, char *username, BOOL reconnect);
void iso_disconnect(void);
void iso_reset_state(void);
/* mcs.c */
STREAM mcs_init(int length);
void mcs_send_to_channel(STREAM s, uint16 channel);
void mcs_send(STREAM s);
STREAM mcs_recv(uint16 * channel, uint8 * rdpver);
BOOL mcs_connect(char *server, STREAM mcs_data, char *username, BOOL reconnect);
void mcs_disconnect(void);
void mcs_reset_state(void);
/* orders.c */
void process_orders(STREAM s, uint16 num_orders);
void reset_order_state(void);
/* rdesktop.c */
void generate_random(uint8 * random);
void *xmalloc(int size);
void exit_if_null(void *ptr);
char *xstrdup(const char *s);
void *xrealloc(void *oldmem, size_t size);
void error(char *format, ...);
void warning(char *format, ...);
void unimpl(char *format, ...);
void hexdump(unsigned char *p, unsigned int len);
/* rdp.c */
static void process_demand_active(STREAM s);
static BOOL process_data_pdu(STREAM s, uint32 * ext_disc_reason);
/* secure.c */
void sec_hash_48(uint8 * out, uint8 * in, uint8 * salt1, uint8 * salt2, uint8 salt);
void sec_hash_16(uint8 * out, uint8 * in, uint8 * salt1, uint8 * salt2);
void buf_out_uint32(uint8 * buffer, uint32 value);
void sec_sign(uint8 * signature, int siglen, uint8 * session_key, int keylen, uint8 * data,
	      int datalen);
void sec_decrypt(uint8 * data, int length);
STREAM sec_init(uint32 flags, int maxlen);
void sec_send_to_channel(STREAM s, uint32 flags, uint16 channel);
void sec_send(STREAM s, uint32 flags);
void sec_process_mcs_data(STREAM s);
STREAM sec_recv(uint8 * rdpver);
BOOL sec_connect(char *server, char *username, BOOL reconnect);
void sec_disconnect(void);
void sec_reset_state(void);
/* tcp.c */
STREAM tcp_init(uint32 maxlen);
void tcp_send(STREAM s);
STREAM tcp_recv(STREAM s, uint32 length);
BOOL tcp_connect(char *server);
void tcp_disconnect(void);
char *tcp_get_address(void);
void tcp_reset_state(void);
