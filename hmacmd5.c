
/*
   Unix SMB/CIFS implementation.
   HMAC MD5 code for use in NTLMv2
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Andrew Tridgell 1992-2000

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc.

   Free Software Foundation
   51 Franklin Street, Fifth Floor
   Boston, MA 02110-1335
   USA

   Telephone: +1-617-542-5942
   Fax: +1-617-542-2652
   General email: info@fsf.org
*/

/* taken direct from rfc2104 implementation and modified for suitable use
 * for ntlmv2.
 */
#ifdef LIBOPENSSL

#include "hmacmd5.h"
#include <string.h>

#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

/***********************************************************************
 the rfc 2104 version of hmac_md5 initialisation.
***********************************************************************/

void hmac_md5_init_rfc2104(const unsigned char *key, int32_t key_len, HMACMD5Context *ctx) {
  int32_t i;
  unsigned char tk[16];

  /* if key is longer than 64 bytes reset it to key=MD5(key) */
  if (key_len > 64) {
    MD5_CTX tctx;

    MD5_Init(&tctx);
    MD5_Update(&tctx, (void *)key, key_len);
    MD5_Final(tk, &tctx);

    key = tk;
    key_len = 16;
  }

  /* start out by storing key in pads */
  ZERO_STRUCT(ctx->k_ipad);
  ZERO_STRUCT(ctx->k_opad);
  memcpy(ctx->k_ipad, key, key_len);
  memcpy(ctx->k_opad, key, key_len);

  /* XOR key with ipad and opad values */
  for (i = 0; i < 64; i++) {
    ctx->k_ipad[i] ^= 0x36;
    ctx->k_opad[i] ^= 0x5c;
  }

  MD5_Init(&ctx->ctx);
  MD5_Update(&ctx->ctx, ctx->k_ipad, 64);
}

/***********************************************************************
 the microsoft version of hmac_md5 initialisation.
***********************************************************************/

void hmac_md5_init_limK_to_64(const unsigned char *key, int32_t key_len, HMACMD5Context *ctx) {
  int32_t i;

  /* if key is longer than 64 bytes truncate it */
  if (key_len > 64) {
    key_len = 64;
  }

  /* start out by storing key in pads */
  ZERO_STRUCT(ctx->k_ipad);
  ZERO_STRUCT(ctx->k_opad);
  memcpy(ctx->k_ipad, key, key_len);
  memcpy(ctx->k_opad, key, key_len);

  /* XOR key with ipad and opad values */
  for (i = 0; i < 64; i++) {
    ctx->k_ipad[i] ^= 0x36;
    ctx->k_opad[i] ^= 0x5c;
  }

  MD5_Init(&ctx->ctx);
  MD5_Update(&ctx->ctx, ctx->k_ipad, 64);
}

/***********************************************************************
 update hmac_md5 "inner" buffer
***********************************************************************/

void hmac_md5_update(const unsigned char *text, int32_t text_len, HMACMD5Context *ctx) { MD5_Update(&ctx->ctx, (void *)text, text_len); /* then text of datagram */ }

/***********************************************************************
 finish off hmac_md5 "inner" buffer and generate outer one.
***********************************************************************/
void hmac_md5_final(unsigned char *digest, HMACMD5Context *ctx) {
  MD5_CTX ctx_o;

  MD5_Final(digest, &ctx->ctx);

  MD5_Init(&ctx_o);
  MD5_Update(&ctx_o, ctx->k_opad, 64);
  MD5_Update(&ctx_o, digest, 16);
  MD5_Final(digest, &ctx_o);
}

/***********************************************************
 single function to calculate an HMAC MD5 digest from data.
 use the microsoft hmacmd5 init method because the key is 16 bytes.
************************************************************/

void hmac_md5(unsigned char key[16], unsigned char *data, int32_t data_len, unsigned char *digest) {
  HMACMD5Context ctx;

  hmac_md5_init_limK_to_64(key, 16, &ctx);
  if (data_len != 0) {
    hmac_md5_update(data, data_len, &ctx);
  }
  hmac_md5_final(digest, &ctx);
}

#endif
