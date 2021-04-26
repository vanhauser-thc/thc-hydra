#include "hydra-mod.h"
#ifndef LIBOPENSSL
void dummy_smb() { printf("\n"); }
#else
#include "hmacmd5.h"
#include "sasl.h"
#include <openssl/des.h>
#include <openssl/md4.h>

// FIXME XXX BUG: several malloc()s without return code checking

/*

http://technet.microsoft.com/en-us/library/cc960646.aspx

   Most of the new code comes from Medusa smbnt module

   ------------------------------------------------------------------------
    Copyright (C) 2009 Joe Mondloch
    JoMo-Kun / jmk@foofus.net

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2,
    as published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    http://www.gnu.org/licenses/gpl.txt

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.

   ------------------------------------------------------------------------

   Based on code from: SMB Auditing Tool
   [Copyright (C) Patrik Karlsson 2001]
   This code allows Hydra to directly test NTLM hashes against
   a Windows. This may be useful for an auditor who has aquired
   a sam._ or pwdump file and would like to quickly determine
   which are valid entries. This module can also be used to test
   SMB passwords against devices that do not allow clear text
   LanMan passwords.

   The "-m 'METHOD'" option is required for this module. The
   following are valid methods: Local, Domain, Hash, Machine,
   NTLMV2, NTLM, LMV2, LM (in quotes).

     Local == Check local account.
     Domain == Check credentials against this hosts primary
          domain controller via this host.
     Hash == Use a NTLM hash rather than a password.
     Machine == Use the Machine's NetBIOS name as the password.
     NTLMV2, NTLM, LMV2, LM == set the dialect

   Be careful of mass domain account lockout with this. For
   example, assume you are checking several accounts against
   many domain workstations. If you are not using the 'L'
   options and these accounts do not exist locally on the
   workstations, each workstation will in turn check their
   respective domain controller. This could cause a bunch of
   lockouts. Of course, it'd look like the workstations, not
   you, were doing it. ;)

   **FYI, this code is unable to test accounts on default XP
   hosts which are not part of a domain and do not have normal
   file sharing enabled. Default XP does not allow shares and
   returns STATUS_LOGON_FAILED for both valid and invalid
   credentials. XP with simple sharing enabled returns SUCCESS
   for both valid and invalid credentials. If anyone knows a
   way to test in these configurations...

*/

#define WIN2000_NATIVEMODE 1
#define WIN_NETBIOSMODE 2

#define PLAINTEXT 10
#define ENCRYPTED 11

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

#ifndef TIME_T_MIN
#define TIME_T_MIN ((time_t)0 < (time_t)-1 ? (time_t)0 : ~(time_t)0 << (sizeof(time_t) * CHAR_BIT - 1))
#endif
#ifndef TIME_T_MAX
#define TIME_T_MAX (~(time_t)0 - TIME_T_MIN)
#endif

#define IVAL_NC(buf, pos) (*(uint32_t *)((char *)(buf) + (pos))) /* Non const version of above. */
#define SIVAL(buf, pos, val) IVAL_NC(buf, pos) = ((uint32_t)(val))

#define TIME_FIXUP_CONSTANT_INT 11644473600LL

extern char *HYDRA_EXIT;
static unsigned char challenge[8];
static unsigned char workgroup[16];
static unsigned char domain[16];
static unsigned char machine_name[16];
int32_t hashFlag, accntFlag, protoFlag;

int32_t smb_auth_mechanism = AUTH_NTLM;
int32_t security_mode = ENCRYPTED;

static size_t UTF8_UTF16LE(unsigned char *in, int32_t insize, unsigned char *out, int32_t outsize) {
  int32_t i = 0, j = 0;
  uint64_t ch;
  if (debug) {
    hydra_report(stderr, "[DEBUG] UTF8_UTF16LE in:\n");
    hydra_dump_asciihex(in, insize);
  }
  for (i = 0; i < insize; i++) {
    if (in[i] < 128) { // one byte
      out[j] = in[i];
      out[j + 1] = 0;
      j = j + 2;
    } else if ((in[i] >= 0xc0) && (in[i] <= 0xdf)) { // Two bytes
      out[j + 1] = 0x07 & (in[i] >> 2);
      out[j] = (0xc0 & (in[i] << 6)) | (0x3f & in[i + 1]);
      j = j + 2;
      i = i + 1;
    } else if ((in[i] >= 0xe0) && (in[i] <= 0xef)) { // Three bytes
      out[j] = (0xc0 & (in[i + 1] << 6)) | (0x3f & in[i + 2]);
      out[j + 1] = (0xf0 & (in[i] << 4)) | (0x0f & (in[i + 1] >> 2));
      j = j + 2;
      i = i + 2;
    } else if ((in[i] >= 0xf0) && (in[i] <= 0xf7)) { // Four bytes
      ch = ((in[i] & 0x07) << 18) + ((0x3f & in[i + 1]) << 12) + ((0x3f & in[i + 2]) << 6) + (0x3f & in[i + 3]) - 0x10000;
      out[j] = (ch >> 10) & 0xff;
      out[j + 1] = 0xd8 | ((ch >> 18) & 0xff);
      out[j + 2] = ch & 0xff;
      out[j + 3] = 0xdc | ((ch >> 8) & 0x3);
      j = j + 4;
      i = i + 3;
    }
    if (j - 2 > outsize)
      break;
  }
  if (debug) {
    hydra_report(stderr, "[DEBUG] UTF8_UTF16LE out:\n");
    hydra_dump_asciihex(out, j);
  }
  return j;
}

static unsigned char Get7Bits(unsigned char *input, int32_t startBit) {
  register uint32_t word;

  word = (unsigned)input[startBit / 8] << 8;
  word |= (unsigned)input[startBit / 8 + 1];

  word >>= 15 - (startBit % 8 + 7);

  return word & 0xFE;
}

/* Make the key */
static void MakeKey(unsigned char *key, unsigned char *DES_key) {
  DES_key[0] = Get7Bits(key, 0);
  DES_key[1] = Get7Bits(key, 7);
  DES_key[2] = Get7Bits(key, 14);
  DES_key[3] = Get7Bits(key, 21);
  DES_key[4] = Get7Bits(key, 28);
  DES_key[5] = Get7Bits(key, 35);
  DES_key[6] = Get7Bits(key, 42);
  DES_key[7] = Get7Bits(key, 49);

  DES_set_odd_parity((DES_cblock *)DES_key);
}

/* Do the DesEncryption */
void DesEncrypt(unsigned char *clear, unsigned char *key, unsigned char *cipher) {
  DES_cblock DES_key;
  DES_key_schedule key_schedule;

  MakeKey(key, DES_key);
  DES_set_key(&DES_key, &key_schedule);
  DES_ecb_encrypt((DES_cblock *)clear, (DES_cblock *)cipher, &key_schedule, 1);
}

/*
  HashLM
  Function: Create a LM hash from the challenge
  Variables:
        lmhash    = the hash created from this function
        pass      = users password
        challenge = the challenge recieved from the server
*/
int32_t HashLM(unsigned char **lmhash, unsigned char *pass, unsigned char *challenge) {
  static unsigned char magic[] = {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
  unsigned char password[14 + 1];
  unsigned char lm_hash[21];
  unsigned char lm_response[24];
  int32_t i = 0, j = 0;
  unsigned char *p = NULL;
  char HexChar;
  int32_t HexValue;

  memset(password, 0, 14 + 1);
  memset(lm_hash, 0, 21);
  memset(lm_response, 0, 24);

  /* Use LM Hash instead of password */
  /* D42E35E1A1E4C22BD32E2170E4857C20:5E20780DD45857A68402938C7629D3B2::: */
  if (hashFlag == 1) {
    p = pass;
    while ((*p != '\0') && (i < 1)) {
      if (*p == ':')
        i++;
      p++;
    }

    if (*p == '\0') {
      hydra_report(stderr, "[ERROR] Reading PwDump file.\n");
      return -1;
    } else if (*p == 'N') {
      if (verbose)
        hydra_report(stderr, "[VERBOSE] Found \"NO PASSWORD\" for LM Hash.\n");

      /* Generate 16-byte LM hash */
      DesEncrypt(magic, &password[0], &lm_hash[0]);
      DesEncrypt(magic, &password[7], &lm_hash[8]);
    } else {
      if (verbose)
        hydra_report(stderr, "[VERBOSE] Convert ASCII PwDump LM Hash (%s).\n", p);
      for (i = 0; i < 16; i++) {
        HexValue = 0x0;
        for (j = 0; j < 2; j++) {
          HexChar = (char)p[2 * i + j];

          if (HexChar > 0x39)
            HexChar = HexChar | 0x20; /* convert upper case to lower */

          if (!(((HexChar >= 0x30) && (HexChar <= 0x39)) ||  /* 0 - 9 */
                ((HexChar >= 0x61) && (HexChar <= 0x66)))) { /* a - f */

            hydra_report(stderr, "[ERROR] Invalid char (%c) for hash.\n", HexChar);
            HexChar = 0x30;
          }

          HexChar -= 0x30;
          if (HexChar > 0x09) /* HexChar is "a" - "f" */
            HexChar -= 0x27;

          HexValue = (HexValue << 4) | (char)HexChar;
        }
        lm_hash[i] = (unsigned char)HexValue;
      }
    }
  } else {
    /* Password == Machine Name */
    if (hashFlag == 2) {
      for (i = 0; i < 16; i++) {
        if (machine_name[i] > 0x39)
          machine_name[i] = machine_name[i] | 0x20; /* convert upper case to lower */
        pass = machine_name;
      }
    }

    /* convert lower case characters to upper case */
    strncpy((char *)password, (char *)pass, 14);
    for (i = 0; i < 14; i++) {
      if ((password[i] >= 0x61) && (password[i] <= 0x7a)) /* a - z */
        password[i] -= 0x20;
    }

    /* Generate 16-byte LM hash */
    DesEncrypt(magic, &password[0], &lm_hash[0]);
    DesEncrypt(magic, &password[7], &lm_hash[8]);
  }

  /*
     NULL-pad 16-byte LM hash to 21-bytes
     Split resultant value into three 7-byte thirds
     DES-encrypt challenge using each third as a key
     Concatenate three 8-byte resulting values to form 24-byte LM response
   */
  DesEncrypt(challenge, &lm_hash[0], &lm_response[0]);
  DesEncrypt(challenge, &lm_hash[7], &lm_response[8]);
  DesEncrypt(challenge, &lm_hash[14], &lm_response[16]);

  memcpy(*lmhash, lm_response, 24);

  return 0;
}

/*
  MakeNTLM
  Function: Create a NTLM hash from the password
*/
int32_t MakeNTLM(unsigned char *ntlmhash, unsigned char *pass) {
  MD4_CTX md4Context;
  unsigned char hash[16];                 /* MD4_SIGNATURE_SIZE = 16 */
  unsigned char unicodePassword[256 * 2]; /* MAX_NT_PASSWORD = 256 */
  int32_t i = 0, j = 0;
  int32_t mdlen;
  unsigned char *p = NULL;
  char HexChar;
  int32_t HexValue;

  /* Use NTLM Hash instead of password */
  if (hashFlag == 1) {
    /* 1000:D42E35E1A1E4C22BD32E2170E4857C20:5E20780DD45857A68402938C7629D3B2:::
     */
    p = pass;
    while ((*p != '\0') && (i < 1)) {
      if (*p == ':')
        i++;
      p++;
    }

    if (*p == '\0') {
      hydra_report(stderr, "[ERROR] reading PWDUMP file.\n");
      return -1;
    }

    for (i = 0; i < 16; i++) {
      HexValue = 0x0;
      for (j = 0; j < 2; j++) {
        HexChar = (char)p[2 * i + j];

        if (HexChar > 0x39)
          HexChar = HexChar | 0x20; /* convert upper case to lower */

        if (!(((HexChar >= 0x30) && (HexChar <= 0x39)) ||  /* 0 - 9 */
              ((HexChar >= 0x61) && (HexChar <= 0x66)))) { /* a - f */
          /*
           *  fprintf(stderr, "Error invalid char (%c) for hash.\n", HexChar);
           *  hydra_child_exit(0);
           */
          HexChar = 0x30;
        }

        HexChar -= 0x30;
        if (HexChar > 0x09) /* HexChar is "a" - "f" */
          HexChar -= 0x27;

        HexValue = (HexValue << 4) | (char)HexChar;
      }
      hash[i] = (unsigned char)HexValue;
    }
  } else {
    /* Password == Machine Name */
    if (hashFlag == 2) {
      for (i = 0; i < 16; i++) {
        if (machine_name[i] > 0x39)
          machine_name[i] = machine_name[i] | 0x20; /* convert upper case to lower */
        pass = machine_name;
      }
    }

    /* Initialize the Unicode version of the secret (== password). */
    /* This implicitly supports most UTF8 characters. */

    j = UTF8_UTF16LE(pass, strlen((char *)pass), unicodePassword, sizeof(unicodePassword));

    mdlen = j; /* length in bytes */

    MD4_Init(&md4Context);
    MD4_Update(&md4Context, unicodePassword, mdlen);
    MD4_Final(hash, &md4Context); /* Tell MD4 we're done */
  }

  memcpy(ntlmhash, hash, 16);
  return 0;
}

/*
  HashLMv2

  This function implements the LMv2 response algorithm. The LMv2 response is
  used to provide pass-through authentication compatibility with older servers.
  The response is based on the NTLM password hash and is exactly 24 bytes.

  The below code is based heavily on the following resources:

    http://davenport.sourceforge.net/ntlm.html#theLmv2Response
    samba-3.0.28a - libsmb/smbencrypt.c
    jcifs - packet capture of LMv2-only connection
*/
int32_t HashLMv2(unsigned char **LMv2hash, unsigned char *szLogin, unsigned char *szPassword) {
  unsigned char ntlm_hash[16];
  unsigned char lmv2_response[24];
  unsigned char unicodeUsername[20 * 2];
  unsigned char unicodeTarget[256 * 2];
  HMACMD5Context ctx;
  unsigned char kr_buf[16];
  int32_t ret, i;
  unsigned char client_challenge[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

  memset(ntlm_hash, 0, 16);
  memset(lmv2_response, 0, 24);
  memset(kr_buf, 0, 16);

  /* --- HMAC #1 Caculations --- */

  /* Calculate and set NTLM password hash */
  ret = MakeNTLM((unsigned char *)&ntlm_hash, (unsigned char *)szPassword);
  if (ret == -1)
    return -1;

  /*
     The Unicode uppercase username is concatenated with the Unicode
     authentication target (the domain or server name specified in the Target
     Name field of the Type 3 message). Note that this calculation always uses
     the Unicode representation, even if OEM encoding has been negotiated; also
     note that the username is converted to uppercase, while the authentication
     target is case-sensitive and must match the case presented in the Target
     Name field.

     The HMAC-MD5 message authentication code algorithm (described in RFC 2104)
     is applied to this value using the 16-byte NTLM hash as the key. This
     results in a 16-byte value - the NTLMv2 hash.
   */

  /* Initialize the Unicode version of the username and target. */
  /* This implicitly supports 8-bit ISO8859/1 characters. */
  /* convert lower case characters to upper case */
  bzero(unicodeUsername, sizeof(unicodeUsername));
  for (i = 0; i < strlen((char *)szLogin); i++) {
    if ((szLogin[i] >= 0x61) && (szLogin[i] <= 0x7a)) /* a - z */
      unicodeUsername[i * 2] = (unsigned char)szLogin[i] - 0x20;
    else
      unicodeUsername[i * 2] = (unsigned char)szLogin[i];
  }

  bzero(unicodeTarget, sizeof(unicodeTarget));
  for (i = 0; i < strlen((char *)workgroup); i++)
    unicodeTarget[i * 2] = (unsigned char)workgroup[i];

  hmac_md5_init_limK_to_64(ntlm_hash, 16, &ctx);
  hmac_md5_update((const unsigned char *)unicodeUsername, 2 * strlen((char *)szLogin), &ctx);
  hmac_md5_update((const unsigned char *)unicodeTarget, 2 * strlen((char *)workgroup), &ctx);
  hmac_md5_final(kr_buf, &ctx);

  /* --- HMAC #2 Calculations --- */
  /*
     The challenge from the Type 2 message is concatenated with our fixed client
     nonce. The HMAC-MD5 message authentication code algorithm is applied to
     this value using the 16-byte NTLMv2 hash (calculated above) as the key.
     This results in a 16-byte output value.
   */

  hmac_md5_init_limK_to_64(kr_buf, 16, &ctx);
  hmac_md5_update((const unsigned char *)challenge, 8, &ctx);
  hmac_md5_update(client_challenge, 8, &ctx);
  hmac_md5_final(lmv2_response, &ctx);

  /* --- 24-byte LMv2 Response Complete --- */
  if ((*LMv2hash = malloc(24)) == NULL)
    return -1;
  memset(*LMv2hash, 0, 24);
  memcpy(*LMv2hash, lmv2_response, 16);
  memcpy(*LMv2hash + 16, client_challenge, 8);

  return 0;
}

/*
  HashNTLMv2

  This function implements the NTLMv2 response algorithm. Support for this
  algorithm was added with Microsoft Windows with NT 4.0 SP4. It should be noted
  that code doesn't currently work with Microsoft Vista. While NTLMv2
  authentication with Samba and Windows 2003 functions as expected, Vista
  systems respond with the oh-so-helpful "INVALID_PARAMETER" error code.
  LMv2-only authentication appears to work against Vista in cases where LM and
  NTLM are refused.

  The below code is based heavily on the following two resources:

    http://davenport.sourceforge.net/ntlm.html#theNtlmv2Response
    samba-3.0.28 - libsmb/smbencrypt.c

  NTLMv2 network authentication is required when attempting to authenticated to
  a system which has the following policy enforced:

  GPO:     "Network Security: LAN Manager authentication level"
  Setting: "Send NTLMv2 response only\refuse LM & NTLM"
*/
int32_t HashNTLMv2(unsigned char **NTLMv2hash, int32_t *iByteCount, unsigned char *szLogin, unsigned char *szPassword) {
  unsigned char ntlm_hash[16];
  unsigned char ntlmv2_response[56 + 20 * 2 + 256 * 2];
  unsigned char unicodeUsername[20 * 2];
  unsigned char unicodeTarget[256 * 2];
  HMACMD5Context ctx;
  unsigned char kr_buf[16];
  int32_t ret, i, iTargetLen;
  unsigned char client_challenge[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

  /*
     -- Example NTLMv2 Response Data --

     [0]       HMAC: (16 bytes)

     [16]      Header: Blob Signature [01 01 00 00] (4 bytes)
     [20]      Reserved: [00 00 00 00] (4 bytes)
     [24]      Time: Little-endian, 64-bit signed value representing the number
     of tenths of a microsecond since January 1, 1601. (8 bytes) [32] Client
     Nonce: (8 bytes) [40]      Unknown: 00 00 00 00 (4 bytes) [44]      Target
     Information (from the Type 2 message) NetBIOS domain/workgroup: Type:
     domain 02 00 (2 bytes) Length: 12 00 (2 bytes) Name: WORKGROUP [NULL
     spacing -> 57 00 4f 00 ...] (18 bytes) End-of-list: 00 00 00 00 (4 bytes)
     Termination: 00 00 00 00 (4 bytes)
   */

  iTargetLen = 2 * strlen((char *)workgroup);

  memset(ntlm_hash, 0, 16);
  memset(ntlmv2_response, 0, 56 + 20 * 2 + 256 * 2);
  memset(kr_buf, 0, 16);

  /* --- HMAC #1 Caculations --- */

  /* Calculate and set NTLM password hash */
  ret = MakeNTLM((unsigned char *)&ntlm_hash, (unsigned char *)szPassword);
  if (ret == -1)
    return -1;

  /*
     The Unicode uppercase username is concatenated with the Unicode
     authentication target (the domain or server name specified in the Target
     Name field of the Type 3 message). Note that this calculation always uses
     the Unicode representation, even if OEM encoding has been negotiated; also
     note that the username is converted to uppercase, while the authentication
     target is case-sensitive and must match the case presented in the Target
     Name field.

     The HMAC-MD5 message authentication code algorithm (described in RFC 2104)
     is applied to this value using the 16-byte NTLM hash as the key. This
     results in a 16-byte value - the NTLMv2 hash.
   */

  /* Initialize the Unicode version of the username and target. */
  /* This implicitly supports 8-bit ISO8859/1 characters. */
  /* convert lower case characters to upper case */
  bzero(unicodeUsername, sizeof(unicodeUsername));
  for (i = 0; i < strlen((char *)szLogin); i++) {
    if ((szLogin[i] >= 0x61) && (szLogin[i] <= 0x7a)) /* a - z */
      unicodeUsername[i * 2] = (unsigned char)szLogin[i] - 0x20;
    else
      unicodeUsername[i * 2] = (unsigned char)szLogin[i];
  }

  bzero(unicodeTarget, sizeof(unicodeTarget));
  for (i = 0; i < strlen((char *)workgroup); i++)
    unicodeTarget[i * 2] = (unsigned char)workgroup[i];

  hmac_md5_init_limK_to_64(ntlm_hash, 16, &ctx);
  hmac_md5_update((const unsigned char *)unicodeUsername, 2 * strlen((char *)szLogin), &ctx);
  hmac_md5_update((const unsigned char *)unicodeTarget, 2 * strlen((char *)workgroup), &ctx);
  hmac_md5_final(kr_buf, &ctx);

  /* --- Blob Construction --- */

  memset(ntlmv2_response + 16, 1, 2); /* Blob Signature 0x01010000 */
  memset(ntlmv2_response + 18, 0, 2);
  memset(ntlmv2_response + 20, 0, 4); /* Reserved */

  /* Time -- Take a Unix time and convert to an NT TIME structure:
     Little-endian, 64-bit signed value representing the number of tenths of a
     microsecond since January 1, 1601.
   */
  struct timespec ts;
  unsigned long long nt;

  ts.tv_sec = (time_t)time(NULL);
  ts.tv_nsec = 0;

  if (ts.tv_sec == 0)
    nt = 0;
  else if (ts.tv_sec == TIME_T_MAX)
    nt = 0x7fffffffffffffffLL;
  else if (ts.tv_sec == (time_t)-1)
    nt = (unsigned long)-1;
  else {
    nt = ts.tv_sec;
    nt += TIME_FIXUP_CONSTANT_INT;
    nt *= 1000 * 1000 * 10; /* nt is now in the 100ns units */
  }

  SIVAL(ntlmv2_response + 24, 0, nt & 0xFFFFFFFF);
  SIVAL(ntlmv2_response + 24, 4, nt >> 32);
  /* End time calculation */

  /* Set client challenge - using a non-random value in this case. */
  memcpy(ntlmv2_response + 32, client_challenge, 8); /* Client Nonce */
  memset(ntlmv2_response + 40, 0, 4);                /* Unknown */

  /* Target Information Block */
  /*
     0x0100 Server name
     0x0200 Domain name
     0x0300 Fully-qualified DNS host name
     0x0400 DNS domain name

     TODO: Need to rework negotiation code to correctly extract target
     information
   */

  memset(ntlmv2_response + 44, 0x02, 1); /* Type: Domain */
  memset(ntlmv2_response + 45, 0x00, 1);
  memset(ntlmv2_response + 46, iTargetLen, 1); /* Length */
  memset(ntlmv2_response + 47, 0x00, 1);

  /* Name of domain or workgroup */
  for (i = 0; i < strlen((char *)workgroup); i++)
    ntlmv2_response[48 + i * 2] = (unsigned char)workgroup[i];

  memset(ntlmv2_response + 48 + iTargetLen, 0, 4); /* End-of-list */

  /* --- HMAC #2 Caculations --- */

  /*
     The challenge from the Type 2 message is concatenated with the blob. The
     HMAC-MD5 message authentication code algorithm is applied to this value
     using the 16-byte NTLMv2 hash (calculated above) as the key. This results
     in a 16-byte output value.
   */

  hmac_md5_init_limK_to_64(kr_buf, 16, &ctx);
  hmac_md5_update(challenge, 8, &ctx);
  hmac_md5_update(ntlmv2_response + 16, 48 - 16 + iTargetLen + 4, &ctx);
  hmac_md5_final(ntlmv2_response, &ctx);

  *iByteCount = 48 + iTargetLen + 4;
  if ((*NTLMv2hash = malloc(*iByteCount)) == NULL)
    return -1;
  memset(*NTLMv2hash, 0, *iByteCount);
  memcpy(*NTLMv2hash, ntlmv2_response, *iByteCount);

  return 0;
}

/*
  HashNTLM
  Function: Create a NTLM hash from the challenge
  Variables:
        ntlmhash  = the hash created from this function
        pass      = users password
        challenge = the challenge recieved from the server
*/
int32_t HashNTLM(unsigned char **ntlmhash, unsigned char *pass, unsigned char *challenge, char *miscptr) {
  int32_t ret;
  unsigned char hash[16]; /* MD4_SIGNATURE_SIZE = 16 */
  unsigned char p21[21];
  unsigned char ntlm_response[24];

  ret = MakeNTLM((unsigned char *)&hash, (unsigned char *)pass);
  if (ret == -1)
    hydra_child_exit(0);

  memset(p21, '\0', 21);
  memcpy(p21, hash, 16);

  DesEncrypt(challenge, p21 + 0, ntlm_response + 0);
  DesEncrypt(challenge, p21 + 7, ntlm_response + 8);
  DesEncrypt(challenge, p21 + 14, ntlm_response + 16);

  memcpy(*ntlmhash, ntlm_response, 24);

  return 0;
}

/*
   NBS Session Request
   Function: Request a new session from the server
   Returns: TRUE on success else FALSE.
*/
int32_t NBSSessionRequest(int32_t s) {
  char nb_name[32];  /* netbiosname */
  char nb_local[32]; /* netbios localredirector */
  unsigned char rqbuf[7] = {0x81, 0x00, 0x00, 0x44, 0x20, 0x00, 0x20};
  char *buf;
  unsigned char rbuf[400];
  int32_t k;

  /* if we are running in native mode (aka port 445) don't do netbios */
  if (protoFlag == WIN2000_NATIVEMODE)
    return 0;

  /* convert computer name to netbios name */
  memset(nb_name, 0, 32);
  memset(nb_local, 0, 32);
  memcpy(nb_name, "CKFDENECFDEFFCFGEFFCCACACACACACA", 32);  /* *SMBSERVER */
  memcpy(nb_local, "EIFJEEFCEBCACACACACACACACACACACA", 32); /* HYDRA */

  if ((buf = (char *)malloc(100)) == NULL)
    return -1;
  memset(buf, 0, 100);
  memcpy(buf, (char *)rqbuf, 5);
  memcpy(buf + 5, nb_name, 32);
  memcpy(buf + 37, (char *)rqbuf + 5, 2);
  memcpy(buf + 39, nb_local, 32);
  memcpy(buf + 71, (char *)rqbuf + 5, 1);

  hydra_send(s, buf, 72, 0);
  free(buf);

  memset(rbuf, 0, 400);
  k = hydra_recv(s, (char *)rbuf, sizeof(rbuf));

  if (k > 0 && (rbuf[0] == 0x82))
    return 0; /* success */
  else
    return -1; /* failed */
}

/*
   SMBNegProt
   Function: Negotiate protocol with server ...
       Actually a pseudo negotiation since the whole
       program counts on NTLM support :)

    The challenge is retrieved from the answer
    No error checking is performed i.e cross your fingers....
*/
int32_t SMBNegProt(int32_t s) {
  unsigned char buf[] = {
      0x00, 0x00, 0x00, 0xbe, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x7d, 0x00, 0x00, 0x01, 0x00, 0x00, 0x9b, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x4d,
      0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f, 0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x53, 0x20, 0x31, 0x2e, 0x30, 0x33, 0x00, 0x02, 0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f, 0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x53, 0x20, 0x33, 0x2e, 0x30, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58,
      0x30, 0x30, 0x32, 0x00, 0x02, 0x44, 0x4f, 0x53, 0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00, 0x02, 0x53, 0x61, 0x6d, 0x62, 0x61, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00

      /*
      0x02,
          0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
          0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52,
          0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02,
          0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f, 0x46,
          0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52,
          0x4b, 0x53, 0x20, 0x31, 0x2e, 0x30, 0x33, 0x00,
          0x02, 0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f,
          0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
          0x52, 0x4b, 0x53, 0x20, 0x33, 0x2e, 0x30, 0x00,
          0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31,
          0x2e, 0x30, 0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e,
          0x32, 0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x53,
          0x61, 0x6d, 0x62, 0x61, 0x00, 0x02, 0x4e, 0x54,
          0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20,
          0x31, 0x2e, 0x30, 0x00, 0x02, 0x4e, 0x54, 0x20,
          0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00
      */
  };

  unsigned char rbuf[400];
  unsigned char sess_key[2];
  unsigned char userid[2] = {0xCD, 0xEF};
  int32_t i = 0, j = 0, k;
  int32_t iLength = 194;
  int32_t iResponseOffset = 73;

  memset((char *)rbuf, 0, 400);

  /* set session key */
  sess_key[1] = getpid() / 100;
  sess_key[0] = getpid() - (100 * sess_key[1]);
  memcpy(buf + 30, sess_key, 2);
  memcpy(buf + 32, userid, 2);

  if (smb_auth_mechanism == AUTH_LM) {
    if (verbose)
      hydra_report(stderr, "[VERBOSE] Setting Negotiate Protocol Response for LM.\n");
    buf[3] = 0xA3;  // Set message length
    buf[37] = 0x80; // Set byte count for dialects
    iLength = 167;
    iResponseOffset = 65;
  }

  hydra_send(s, (char *)buf, iLength, 0);
  k = hydra_recv(s, (char *)rbuf, sizeof(rbuf));
  if (k == 0)
    return 3;

  /* retrieve the security mode */
  /*
     [0] Mode:       (0) ?                                 (1) USER security
     mode [1] Password:   (0) PLAINTEXT password                (1) ENCRYPTED
     password. Use challenge/response [2] Signatures: (0) Security signatures
     NOT enabled   (1) ENABLED [3] Sig Req:    (0) Security signatures NOT
     required  (1) REQUIRED

     SAMBA: 0x01 (default)
     WinXP: 0x0F (default)
     WinXP: 0x07 (Windows 2003 / DC)
   */
  switch (rbuf[39]) {
  case 0x01:
    // real plaintext should be used with LM auth
    if (verbose)
      hydra_report(stderr, "[VERBOSE] Server requested PLAINTEXT password.\n");
    security_mode = PLAINTEXT;

    if (hashFlag == 1) {
      if (verbose)
        hydra_report(stderr, "[VERBOSE] Server requested PLAINTEXT password. HASH "
                             "password mode not supported for this configuration.\n");
      return 3;
    }
    if (hashFlag == 2) {
      if (verbose)
        hydra_report(stderr, "[VERBOSE] Server requested PLAINTEXT password. MACHINE "
                             "password mode not supported for this configuration.\n");
      return 3;
    }
    break;
  case 0x03:
    if (verbose)
      hydra_report(stderr, "[VERBOSE] Server requested ENCRYPTED password "
                           "without security signatures.\n");
    security_mode = ENCRYPTED;
    break;
  case 0x07:
  case 0x0F:
    if (verbose)
      hydra_report(stderr, "[VERBOSE] Server requested ENCRYPTED password.\n");
    security_mode = ENCRYPTED;
    break;
  default:
    if (verbose)
      hydra_report(stderr,
                   "[VERBOSE] Unknown security mode request: %2.2X. Proceeding "
                   "using ENCRYPTED password mode.\n",
                   rbuf[39]);
    security_mode = ENCRYPTED;
    break;
  }

  /* Retrieve the challenge */
  memcpy(challenge, (char *)rbuf + iResponseOffset, sizeof(challenge));

  /* Find the primary domain/workgroup name */
  memset(workgroup, 0, 16);
  memset(machine_name, 0, 16);

  // seems using LM only the domain is returned not the server
  // and the domain is not padded with null chars
  if (smb_auth_mechanism == AUTH_LM) {
    while ((rbuf[iResponseOffset + 8 + i] != 0) && (i < 16)) {
      workgroup[i] = rbuf[iResponseOffset + 8 + i];
      i++;
    }
  } else {
    while ((rbuf[iResponseOffset + 8 + i * 2] != 0) && (i < 16)) {
      workgroup[i] = rbuf[iResponseOffset + 8 + i * 2];
      i++;
    }

    while ((rbuf[iResponseOffset + 8 + (i + j + 1) * 2] != 0) && (j < 16)) {
      machine_name[j] = rbuf[iResponseOffset + 8 + (i + j + 1) * 2];
      j++;
    }
  }

  if (verbose) {
    hydra_report(stderr, "[VERBOSE] Server machine name: %s\n", machine_name);
    hydra_report(stderr, "[VERBOSE] Server primary domain: %s\n", workgroup);
  }
  // success
  return 2;
}

/*
  SMBSessionSetup
  Function: Send username + response to the challenge from
            the server.
  Returns: TRUE on success else FALSE.
*/
unsigned long SMBSessionSetup(int32_t s, char *szLogin, char *szPassword, char *miscptr) {
  unsigned char buf[512];
  unsigned char *LMv2hash = NULL;
  unsigned char *NTLMv2hash = NULL;
  unsigned char *NTLMhash = NULL;
  unsigned char *LMhash = NULL;
  //  unsigned char unicodeLogin[32 * 2];
  int32_t j;
  char bufReceive[512];
  int32_t nReceiveBufferSize = 0;
  int32_t ret;
  int32_t iByteCount = 0, iOffset = 0;

  if (accntFlag == 0) {
    strcpy((char *)workgroup, "localhost");

  } else if (accntFlag == 2) {
    memset(workgroup, 0, 16);
  }
  // domain flag is not needed here, it will be auto set,
  // below it's domain specified on cmd line
  else if (accntFlag == 4) {
    strncpy((char *)workgroup, (char *)domain, 16);
  }

  /* NetBIOS Session Service */
  unsigned char szNBSS[4] = {
      0x00,            /* Message Type: Session Message */
      0x00, 0x00, 0x85 /* Length -- MUST SET */
  };

  /* SMB Header */
  unsigned char szSMB[32] = {
      0xff,
      0x53,
      0x4d,
      0x42, /* Server Component */
      0x73, /* SMB Command: Session Setup AndX */
      0x00,
      0x00,
      0x00,
      0x00, /* NT Status: STATUS_SUCCESS */
      0x08, /* Flags */
      0x01,
      0xc0,
      /* Flags2 */ /* add Unicode */
      0x00,
      0x00, /* Process ID High */
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00, /* Signature */
      0x00,
      0x00, /* Reserved */
      0x00,
      0x00, /* Tree ID */
      0x13,
      0x37, /* Process ID */
      0x00,
      0x00, /* User ID */
      0x01,
      0x00 /* Multiplx ID */
  };

  memset(buf, 0, 512);
  memcpy(buf, szNBSS, 4);
  memcpy(buf + 4, szSMB, 32);

  if (security_mode == ENCRYPTED) {
    /* Session Setup AndX Request */
    if (smb_auth_mechanism == AUTH_LM) {
      if (verbose)
        hydra_report(stderr, "[VERBOSE] Attempting LM password authentication.\n");

      unsigned char szSessionRequest[23] = {
          0x0a,                   /* Word Count */
          0xff,                   /* AndXCommand: No further commands */
          0x00,                   /* Reserved */
          0x00, 0x00,             /* AndXOffset */
          0xff, 0xff,             /* Max Buffer */
          0x02, 0x00,             /* Max Mpx Count */
          0x3c, 0x7d,             /* VC Number */
          0x00, 0x00, 0x00, 0x00, /* Session Key */
          0x18, 0x00,             /* LAN Manager Password Hash Length */
          0x00, 0x00, 0x00, 0x00, /* Reserved */
          0x49, 0x00              /* Byte Count -- MUST SET */
      };

      iOffset = 59;    /* szNBSS + szSMB + szSessionRequest */
      iByteCount = 24; /* Start with length of LM hash */

      /* Set Session Setup AndX Request header information */
      memcpy(buf + 36, szSessionRequest, 23);

      /* Calculate and set LAN Manager password hash */
      if ((LMhash = (unsigned char *)malloc(24)) == NULL)
        return -1;
      memset(LMhash, 0, 24);

      ret = HashLM(&LMhash, (unsigned char *)szPassword, (unsigned char *)challenge);
      if (ret == -1) {
        free(LMhash);
        return -1;
      }

      memcpy(buf + iOffset, LMhash, 24);
      free(LMhash);

    } else if (smb_auth_mechanism == AUTH_NTLM) {
      if (verbose)
        hydra_report(stderr, "[VERBOSE] Attempting NTLM password authentication.\n");

      unsigned char szSessionRequest[29] = {
          0x0d, /* Word Count */
          0xff, /* AndXCommand: No further commands */
          0x00, /* Reserved */
          0x00,
          0x00, /* AndXOffset */
          0xff,
          0xff, /* Max Buffer */
          0x02,
          0x00, /* Max Mpx Count */
          0x3c,
          0x7d, /* VC Number */
          0x00,
          0x00,
          0x00,
          0x00, /* Session Key */
          0x18,
          0x00, /* LAN Manager Password Hash Length */
          0x18,
          0x00, /* NT LAN Manager Password Hash Length */
          0x00,
          0x00,
          0x00,
          0x00, /* Reserved */
          0x5c,
          0x00,
          0x00,
          0x00,
          /* Capabilities */ /* Add Unicode */
          0x49,
          0x00 /* Byte Count -- MUST SET */
      };

      iOffset = 65;    /* szNBSS + szSMB + szSessionRequest */
      iByteCount = 48; /* Start with length of NTLM and LM hashes */

      /* Set Session Setup AndX Request header information */
      memcpy(buf + 36, szSessionRequest, 29);

      /* Calculate and set NTLM password hash */
      if ((NTLMhash = (unsigned char *)malloc(24)) == NULL)
        return -1;
      memset(NTLMhash, 0, 24);

      /* We don't need to actually calculated a LM hash for this mode, only NTLM
       */
      ret = HashNTLM(&NTLMhash, (unsigned char *)szPassword, (unsigned char *)challenge, miscptr);
      if (ret == -1)
        return -1;

      memcpy(buf + iOffset + 24, NTLMhash, 24); /* Skip space for LM hash */
      free(NTLMhash);
    } else if (smb_auth_mechanism == AUTH_LMv2) {
      if (verbose)
        hydra_report(stderr, "[VERBOSE] Attempting LMv2 password authentication.\n");

      unsigned char szSessionRequest[29] = {
          0x0d,                   /* Word Count */
          0xff,                   /* AndXCommand: No further commands */
          0x00,                   /* Reserved */
          0x00, 0x00,             /* AndXOffset */
          0xff, 0xff,             /* Max Buffer */
          0x02, 0x00,             /* Max Mpx Count */
          0x3c, 0x7d,             /* VC Number */
          0x00, 0x00, 0x00, 0x00, /* Session Key */
          0x18, 0x00,             /* LAN Manager Password Hash Length */
          0x00, 0x00,             /* NT LAN Manager Password Hash Length */
          0x00, 0x00, 0x00, 0x00, /* Reserved */
          0x50, 0x00, 0x00, 0x00, /* Capabilities */
          0x49, 0x00              /* Byte Count -- MUST SET */
      };

      iOffset = 65;    /* szNBSS + szSMB + szSessionRequest */
      iByteCount = 24; /* Start with length of LMv2 response */

      /* Set Session Setup AndX Request header information */
      memcpy(buf + 36, szSessionRequest, 29);

      /* Calculate and set LMv2 response hash */
      if ((LMv2hash = (unsigned char *)malloc(24)) == NULL)
        return -1;
      memset(LMv2hash, 0, 24);

      ret = HashLMv2(&LMv2hash, (unsigned char *)szLogin, (unsigned char *)szPassword);
      if (ret == -1) {
        free(LMv2hash);
        return -1;
      }

      memcpy(buf + iOffset, LMv2hash, 24);
      free(LMv2hash);
    } else if (smb_auth_mechanism == AUTH_NTLMv2) {
      if (verbose)
        hydra_report(stderr, "[VERBOSE] Attempting LMv2/NTLMv2 password authentication.\n");

      unsigned char szSessionRequest[29] = {
          0x0d,                   /* Word Count */
          0xff,                   /* AndXCommand: No further commands */
          0x00,                   /* Reserved */
          0x00, 0x00,             /* AndXOffset */
          0xff, 0xff,             /* Max Buffer */
          0x02, 0x00,             /* Max Mpx Count */
          0x3c, 0x7d,             /* VC Number */
          0x00, 0x00, 0x00, 0x00, /* Session Key */
          0x18, 0x00,             /* LMv2 Response Hash Length */
          0x4b, 0x00,             /* NTLMv2 Response Hash Length -- MUST SET */
          0x00, 0x00, 0x00, 0x00, /* Reserved */
          0x50, 0x00, 0x00, 0x00, /* Capabilities */
          0x49, 0x00              /* Byte Count -- MUST SET */
      };

      iOffset = 65; /* szNBSS + szSMB + szSessionRequest */

      /* Set Session Setup AndX Request header information */
      memcpy(buf + 36, szSessionRequest, 29);

      /* Calculate and set LMv2 response hash */
      ret = HashLMv2(&LMv2hash, (unsigned char *)szLogin, (unsigned char *)szPassword);
      if (ret == -1)
        return -1;

      memcpy(buf + iOffset, LMv2hash, 24);
      free(LMv2hash);

      /* Calculate and set NTLMv2 response hash */
      ret = HashNTLMv2(&NTLMv2hash, &iByteCount, (unsigned char *)szLogin, (unsigned char *)szPassword);
      if (ret == -1)
        return -1;

      /* Set NTLMv2 Response Length */
      memset(buf + iOffset - 12, iByteCount, 1);
      if (verbose)
        hydra_report(stderr, "[VERBOSE] HashNTLMv2 response length: %d\n", iByteCount);

      memcpy(buf + iOffset + 24, NTLMv2hash, iByteCount);
      free(NTLMv2hash);

      iByteCount += 24; /* Reflects length of both LMv2 and NTLMv2 responses */
    }
  } else if (security_mode == PLAINTEXT) {
    if (verbose)
      hydra_report(stderr, "[VERBOSE] Attempting PLAINTEXT password authentication.\n");

    unsigned char szSessionRequest[23] = {
        0x0a,                   /* Word Count */
        0xff,                   /* AndXCommand: No further commands */
        0x00,                   /* Reserved */
        0x00, 0x00,             /* AndXOffset */
        0xff, 0xff,             /* Max Buffer */
        0x02, 0x00,             /* Max Mpx Count */
        0x3c, 0x7d,             /* VC Number */
        0x00, 0x00, 0x00, 0x00, /* Session Key */
        0x00, 0x00,             /* Password Length -- MUST SET */
        0x00, 0x00, 0x00, 0x00, /* Reserved */
        0x49, 0x00              /* Byte Count -- MUST SET */
    };

    iOffset = 59; /* szNBSS + szSMB + szSessionRequest */

    /* Set Session Setup AndX Request header information */
    memcpy(buf + 36, szSessionRequest, 23);

    /* Calculate and set password length */
    /* Samba appears to append NULL characters equal to the password length plus
     * 2 */
    // iByteCount = 2 * strlen(szPassword) + 2;
    iByteCount = strlen(szPassword) + 1;
    buf[iOffset - 8] = (iByteCount) % 256;
    buf[iOffset - 7] = (iByteCount) / 256;

    /* set ANSI password */
    /*
       Depending on the SAMBA server configuration, multiple passwords may be
       successful when dealing with mixed-case values. The SAMBA parameter
       "password level" appears to determine how many characters within a
       password are tested by the server both upper and lower case. For example,
       assume a SAMBA account has a password of "Fred" and the server is
       configured with "password level = 2". Medusa sends the password "FRED".
       The SAMBA server will brute-force test this value for us with values
       like: "FRed", "FrEd", "FreD", "fREd", "fReD", "frED", ... The default
       setting is "password level = 0". This results in only two attempts to
       being made by the remote server; the password as is and the password in
       all-lower case.
     */
    strncpy((char *)(buf + iOffset), szPassword, 256);
  } else {
    hydra_report(stderr, "[ERROR] Security_mode was not properly set. This "
                         "should not happen.\n");
    return -1;
  }

  /* Set account and workgroup values */

  j = UTF8_UTF16LE((unsigned char *)szLogin, strlen(szLogin), buf + iOffset + iByteCount + 1, 2 * strlen(szLogin));
  iByteCount += j + 3; /* NULL pad account name */
  j = UTF8_UTF16LE(workgroup, strlen((char *)workgroup), buf + iOffset + iByteCount, 2 * strlen((char *)workgroup));
  iByteCount += j + 2; // NULL pad workgroup name

  /* Set native OS and LAN Manager values */

  char *szOSName = "Unix";
  j = UTF8_UTF16LE((unsigned char *)szOSName, strlen(szOSName), buf + iOffset + iByteCount, 2 * sizeof(szOSName));
  iByteCount += j + 2; // NULL terminated
  char *szLANMANName = "Samba";
  j = UTF8_UTF16LE((unsigned char *)szLANMANName, strlen(szLANMANName), buf + iOffset + iByteCount, 2 * sizeof(szLANMANName));
  iByteCount += j + 2; // NULL terminated

  /* Set the header length */
  buf[2] = (iOffset - 4 + iByteCount) / 256;
  buf[3] = (iOffset - 4 + iByteCount) % 256;

  if (verbose)
    hydra_report(stderr, "[VERBOSE] Set NBSS header length: %2.2X\n", buf[3]);

  /* Set data byte count */
  buf[iOffset - 2] = iByteCount;
  if (verbose)
    hydra_report(stderr, "[VERBOSE] Set byte count: %2.2X\n", buf[57]);

  hydra_send(s, (char *)buf, iOffset + iByteCount, 0);

  nReceiveBufferSize = hydra_recv(s, bufReceive, sizeof(bufReceive));
  if (/*(bufReceive == NULL) ||*/ (nReceiveBufferSize == 0))
    return -1;

  /* 41 - Action (Guest/Non-Guest Account) */
  /*  9 - NT Status (Error code) */
  return (((bufReceive[41] & 0x01) << 24) | ((bufReceive[11] & 0xFF) << 16) | ((bufReceive[10] & 0xFF) << 8) | (bufReceive[9] & 0xFF));
}

int32_t start_smb(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass;
  int32_t SMBerr, SMBaction;
  unsigned long SMBSessionRet;
  char ipaddr_str[64];
  char ErrorCode[10];

  memset(&ErrorCode, 0, 10);

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  strncpy(ipaddr_str, hydra_address2string(ip), sizeof(ipaddr_str) - 1);

  SMBSessionRet = SMBSessionSetup(s, login, pass, miscptr);
  if (SMBSessionRet == -1)
    return 3;
  SMBerr = (unsigned long)SMBSessionRet & 0x00FFFFFF;
  SMBaction = ((unsigned long)SMBSessionRet & 0xFF000000) >> 24;

  if (verbose)
    hydra_report(stderr, "[VERBOSE] SMBSessionRet: %8.8X SMBerr: %4.4X SMBaction: %2.2X\n", (uint32_t)SMBSessionRet, SMBerr, SMBaction);

  /*
     some error code are available here:
     http://msdn.microsoft.com/en-us/library/ee441884(v=prot.13).aspx
   */

  if (SMBerr == 0x000000) {  /* success */
    if (SMBaction == 0x01) { /* invalid account - anonymous connection */
      fprintf(stderr,
              "[%d][smb] Host: %s Account: %s Error: Invalid account "
              "(Anonymous success)\n",
              port, ipaddr_str, login);
      hydra_completed_pair_skip();
    } else { /* valid account */
      hydra_report_found_host(port, ip, "smb", fp);
      hydra_completed_pair_found();
    }
  } else if ((SMBerr == 0x00000D) && (SMBaction == 0x00)) {
    hydra_report(stderr, "[ERROR] Invalid parameter status received, either "
                         "the account or the method used are not valid\n");
    hydra_completed_pair_skip();
  } else if (SMBerr == 0x00006E) { /* Valid password, GPO Disabling Remote
                                      Connections Using NULL Passwords */
    hydra_report(stdout,
                 "[%d][smb] Host: %s Account: %s Valid password, GPO Disabling "
                 "Remote Connections Using NULL Passwords\n",
                 port, ipaddr_str, login);
    hydra_report_found_host(port, ip, "smb", fp);
    hydra_completed_pair_found();
  } else if (SMBerr == 0x00015B) { /* Valid password, GPO "Deny access to this
                                      computer from the network" */
    hydra_report(stdout,
                 "[%d][smb] Host: %s Account: %s Valid password, GPO Deny "
                 "access to this computer from the network\n",
                 port, ipaddr_str, login);
    hydra_report_found_host(port, ip, "smb", fp);
    hydra_completed_pair_found();
  } else if (SMBerr == 0x000193) { /* Valid password, account expired  */
    hydra_report(stdout, "[%d][smb] Host: %s Account: %s Valid password, account expired\n", port, ipaddr_str, login);
    hydra_report_found_host(port, ip, "smb", fp);
    hydra_completed_pair_found();
  } else if ((SMBerr == 0x000224) || (SMBerr == 0xC20002)) { /* Valid password, account expired  */
    hydra_report(stdout,
                 "[%d][smb] Host: %s Account: %s Valid password, password "
                 "expired and must be changed on next logon\n",
                 port, ipaddr_str, login);
    hydra_report_found_host(port, ip, "smb", fp);
    hydra_completed_pair_found();
  } else if ((SMBerr == 0x00006F) || (SMBerr == 0xC10002)) { /* Invalid logon hours  */
    hydra_report(stdout,
                 "[%d][smb] Host: %s Account: %s Valid password, but logon "
                 "hours invalid\n",
                 port, ipaddr_str, login);
    hydra_report_found_host(port, ip, "smb", fp);
    hydra_completed_pair_found();
  } else if (SMBerr == 0x050001) { /* AS/400 -- Incorrect password */
    hydra_report(stdout,
                 "[%d][smb] Host: %s Account: %s Error: Incorrect password or "
                 "account disabled\n",
                 port, ipaddr_str, login);
    if ((miscptr) && (strstr(miscptr, "LM")))
      hydra_report(stderr, "[INFO] LM dialect may be disabled, try LMV2 instead\n");
    hydra_completed_pair_skip();
  } else if (SMBerr == 0x000024) { /* change password on next login [success] */
    hydra_report(stdout, "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD\n", port, ipaddr_str, login);
    hydra_completed_pair_found();
  } else if (SMBerr == 0x00006D) { /* STATUS_LOGON_FAILURE */
    hydra_completed_pair();
  } else if (SMBerr == 0x000071) { /* password expired */
    if (verbose)
      fprintf(stderr, "[%d][smb] Host: %s Account: %s Error: PASSWORD EXPIRED\n", port, ipaddr_str, login);
    hydra_completed_pair_skip();
  } else if ((SMBerr == 0x000072) || (SMBerr == 0xBF0002)) { /* account disabled */ /* BF0002 on w2k */
    if (verbose)
      fprintf(stderr, "[%d][smb] Host: %s Account: %s Error: ACCOUNT_DISABLED\n", port, ipaddr_str, login);
    hydra_completed_pair_skip();
  } else if (SMBerr == 0x000034 || SMBerr == 0x000234) { /* account locked out */
    if (verbose)
      fprintf(stderr, "[%d][smb] Host: %s Account: %s Error: ACCOUNT_LOCKED\n", port, ipaddr_str, login);
    hydra_completed_pair_skip();
  } else if (SMBerr == 0x00008D) { /* ummm... broken client-domain membership  */
    if (verbose)
      fprintf(stderr,
              "[%d][smb] Host: %s Account: %s Error: "
              "NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE\n",
              port, ipaddr_str, login);
    hydra_completed_pair();
  } else { /* failed */
    if (verbose)
      fprintf(stderr, "[%d][smb] Host: %s Account: %s Unknown Error: %6.6X\n", port, ipaddr_str, login, SMBerr);
    hydra_completed_pair();
  }

  hydra_disconnect(s);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 1;
}

void service_smb(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;

  // default is both (local and domain) checks and normal passwd
  accntFlag = 2; // BOTH
  hashFlag = 0;  // PASS
  smb_auth_mechanism = AUTH_NTLM;

  if (miscptr) {
    // check group
    strupper(miscptr);
    if (strstr(miscptr, "OTHER_DOMAIN:") != NULL) {
      char *tmpdom;
      int32_t err = 0;

      accntFlag = 4; // OTHER DOMAIN
      tmpdom = strstr(miscptr, "OTHER_DOMAIN:");
      tmpdom = tmpdom + strlen("OTHER_DOMAIN:");

      if (tmpdom) {
        // split the string after the domain if there are other values
        strtok(tmpdom, " ");
        if (tmpdom) {
          strncpy((char *)domain, (char *)tmpdom, sizeof(domain) - 1);
          domain[sizeof(domain) - 1] = 0;
        } else {
          err = 1;
        }
      } else {
        err = 1;
      }

      if (err) {
        if (verbose)
          hydra_report(stdout, "[VERBOSE] requested line mode\n");
        accntFlag = 2;
      }
    } else if (strstr(miscptr, "LOCAL") != NULL) {
      accntFlag = 0; // LOCAL
    } else if (strstr(miscptr, "DOMAIN") != NULL) {
      accntFlag = 1; // DOMAIN
    }
    // check pass
    if (strstr(miscptr, "HASH") != NULL) {
      hashFlag = 1;
    } else if (strstr(miscptr, "MACHINE") != NULL) {
      hashFlag = 2;
    }
    // check auth
    if (strstr(miscptr, "NTLMV2") != NULL) {
      smb_auth_mechanism = AUTH_NTLMv2;
    } else if (strstr(miscptr, "NTLM") != NULL) {
      smb_auth_mechanism = AUTH_NTLM;
    } else if (strstr(miscptr, "LMV2") != NULL) {
      smb_auth_mechanism = AUTH_LMv2;
    } else if (strstr(miscptr, "LM") != NULL) {
      smb_auth_mechanism = AUTH_LM;
    }
  }
  if (verbose) {
    hydra_report(stdout, "[VERBOSE] accntFlag is %d\n", accntFlag);
    hydra_report(stdout, "[VERBOSE] hashFlag is %d\n", accntFlag);
  }

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  for (;;) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      //      usleepn(300);

      if (port != 0) {
        sock = hydra_connect_tcp(ip, port);
        if (port == PORT_SMB) {
          protoFlag = WIN_NETBIOSMODE;
          if (verbose)
            hydra_report(stderr, "[VERBOSE] Attempting NETBIOS mode.\n");
        } else {
          protoFlag = WIN2000_NATIVEMODE;
          if (verbose)
            hydra_report(stderr, "[VERBOSE] Attempting WIN2K Native mode.\n");
        }
      } else {
        sock = hydra_connect_tcp(ip, PORT_SMBNT);
        if (sock > 0) {
          port = PORT_SMBNT;
          protoFlag = WIN2000_NATIVEMODE;
        } else {
          hydra_report(stderr, "Failed to establish WIN2000_NATIVE mode. "
                               "Attempting WIN_NETBIOS mode.\n");
          port = PORT_SMB;
          protoFlag = WIN_NETBIOSMODE;
          sock = hydra_connect_tcp(ip, PORT_SMB);
        }
      }
      if (sock < 0) {
        if (quiet != 1)
          fprintf(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      if (NBSSessionRequest(sock) < 0) {
        fprintf(stderr, "[ERROR] Session Setup Failed (is the server service running?)\n");
        hydra_child_exit(2);
      }
      next_run = SMBNegProt(sock);
      break;
    case 2: /* run the cracking function */
      next_run = start_smb(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    default:
      fprintf(stderr, "[ERROR] Caught unknown return code (%d), exiting!\n", run);
      hydra_child_exit(0);
    }
    run = next_run;
  }
}
#endif

int32_t service_smb_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  //
  // fill if needed.
  //
  // return codes:
  //   0 all OK
  //   -1  error, hydra will exit, so print a good error message here
  time_t ctime;
  int ready = 0, sock = hydra_connect_tcp(ip, port);
  unsigned char buf[] = {0x00, 0x00, 0x00, 0xbe, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x43, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9b, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x4d,
                         0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f, 0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x53, 0x20, 0x31, 0x2e, 0x30, 0x33, 0x00, 0x02, 0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f, 0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x53, 0x20, 0x33, 0x2e, 0x30, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58,
                         0x30, 0x30, 0x32, 0x00, 0x02, 0x44, 0x4f, 0x53, 0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00, 0x02, 0x53, 0x61, 0x6d, 0x62, 0x61, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00};

  if (sock < 0) {
    fprintf(stderr, "[ERROR] could not connect to target smb://%s:%d/\n", hostname, port);
    return -1;
  }

  if (send(sock, buf, sizeof(buf), 0) < 0) {
    fprintf(stderr, "[ERROR] unable to send to target smb://%s:%d/\n", hostname, port);
    return -1;
  }

  ctime = time(NULL);
  do {
    usleepn(300);
  } while ((ready = hydra_data_ready(sock)) <= 0 && ctime + 5 >= time(NULL));

  if (ready <= 0) {
    fprintf(stderr, "[ERROR] no reply from target smb://%s:%d/\n", hostname, port);
    return -1;
  }

  if ((ready = recv(sock, buf, sizeof(buf), 0)) < 40) {
    fprintf(stderr, "[ERROR] invalid reply from target smb://%s:%d/\n", hostname, port);
    return -1;
  }

  close(sock);

  if (buf[37] == buf[38] && buf[38] == 0xff) {
    fprintf(stderr, "[ERROR] target smb://%s:%d/ does not support SMBv1\n", hostname, port);
    return -1;
  }

  if ((buf[15] & 16) == 16) {
    fprintf(stderr,
            "[ERROR] target smb://%s:%d/ requires signing which we do not "
            "support\n",
            hostname, port);
    return -1;
  }

  return 0;
}

void usage_smb(const char *service) {
  printf("Module smb default value is set to test both local and domain account, "
         "using a simple password with NTLM dialect.\n"
         "Note: you can set the group type using LOCAL or DOMAIN keyword\n"
         "      or other_domain:{value} to specify a trusted domain.\n"
         "      you can set the password type using HASH or MACHINE keyword\n"
         "      (to use the Machine's NetBIOS name as the password).\n"
         "      you can set the dialect using NTLMV2, NTLM, LMV2, LM keyword.\n"
         "Example: \n"
         "      hydra smb://microsoft.com  -l admin -p tooeasy -m \"local lmv2\"\n"
         "      hydra smb://microsoft.com  -l admin -p "
         "D5731CFC6C2A069C21FD0D49CAEBC9EA:2126EE7712D37E265FD63F2C84D2B13D::: -m "
         "\"local hash\"\n"
         "      hydra smb://microsoft.com  -l admin -p tooeasy -m "
         "\"other_domain:SECONDDOMAIN\"\n\n");
}
