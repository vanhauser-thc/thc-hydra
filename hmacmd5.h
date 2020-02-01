/*
   Unix SMB/CIFS implementation.
   Interface header: Scheduler service
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   Copyright (C) Andrew Tridgell 1992-1999

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

#ifdef __sun
#include <sys/int_types.h>
#elif defined(__FreeBSD__) || defined(__IBMCPP__) || defined(_AIX)
#include <inttypes.h>
#else
#include <stdint.h>
#endif
#include <openssl/md5.h>
#ifndef _HMAC_MD5_H

typedef struct {
  MD5_CTX ctx;
  unsigned char k_ipad[65];
  unsigned char k_opad[65];
} HMACMD5Context;

#endif /* _HMAC_MD5_H */

void hmac_md5_init_rfc2104(const unsigned char *key, int32_t key_len, HMACMD5Context *ctx);
void hmac_md5_init_limK_to_64(const unsigned char *key, int32_t key_len, HMACMD5Context *ctx);
void hmac_md5_update(const unsigned char *text, int32_t text_len, HMACMD5Context *ctx);
void hmac_md5_final(unsigned char *digest, HMACMD5Context *ctx);
void hmac_md5(unsigned char key[16], unsigned char *data, int32_t data_len, unsigned char *digest);
