
/*
   david: this module is heavily based on rdesktop v 1.7.0

   rdesktop: A Remote Desktop Protocol client.
   Protocol services - RDP layer
   Copyright (C) Matthew Chapman <matthewc.unsw.edu.au> 1999-2008
   Copyright 2003-2011 Peter Astrand <astrand@cendio.se> for Cendio AB

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

note:

this module was tested on w2k, xp, w2k3, w2k8

in terminal services configuration, in rdp-tcp properties
in Logon Settings tab, if 'Always prompt for password' is checked,
the password can't be passed interactively so there is no way
to test the credential (unless manually).

it's advised to lower the number of parallel tasks as RDP server
can't handle multiple connections at the same time.
It's particularly true on windows XP

*/

#ifndef LIBOPENSSL
#include <stdio.h>
void dummy_rdp() {
  printf("\n");
}
#else

#include "rdp.h"
extern char *HYDRA_EXIT;

BOOL g_encryption = True;
BOOL g_use_rdp5 = True;
BOOL g_console_session = False;
BOOL g_bitmap_cache = True;
BOOL g_bitmap_cache_persist_enable = False;
BOOL g_bitmap_compression = True;
BOOL g_desktop_save = True;
int g_server_depth = -1;
int os_version = 0;             //2000

uint32 g_rdp5_performanceflags = RDP5_NO_WALLPAPER | RDP5_NO_FULLWINDOWDRAG | RDP5_NO_MENUANIMATIONS;

/* Session Directory redirection */
BOOL g_redirect = False;
uint32 g_redirect_flags = 0;

uint32 g_reconnect_logonid = 0;
char g_reconnect_random[16];
BOOL g_has_reconnect_random = False;
uint8 g_client_random[SEC_RANDOM_SIZE];

/*
  0 unknown
  1 success
  2 failed
*/
#define LOGIN_UNKN 0
#define LOGIN_SUCC 1
#define LOGIN_FAIL 2
int login_result = LOGIN_UNKN;

uint8 *g_next_packet;
uint32 g_rdp_shareid;

/* Called during redirection to reset the state to support redirection */
void rdp_reset_state(void) {
  g_next_packet = NULL;         /* reset the packet information */
  g_rdp_shareid = 0;
  sec_reset_state();
}

static void rdesktop_reset_state(void) {
  rdp_reset_state();
}

static RDP_ORDER_STATE g_order_state;

#define TCP_STRERROR strerror(errno)
#define TCP_BLOCKS (errno == EWOULDBLOCK)


#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long) -1)
#endif

#define STREAM_COUNT 1


int g_sock;
static struct stream g_in;
static struct stream g_out[STREAM_COUNT];

/* wait till socket is ready to write or timeout */
static BOOL tcp_can_send(int sck, int millis) {
  fd_set wfds;
  struct timeval time;
  int sel_count;

  time.tv_sec = millis / 1000;
  time.tv_usec = (millis * 1000) % 1000000;
  FD_ZERO(&wfds);
  FD_SET(sck, &wfds);
  sel_count = select(sck + 1, 0, &wfds, 0, &time);
  if (sel_count > 0) {
    return True;
  }
  return False;
}

/* Initialise TCP transport data packet */
STREAM tcp_init(uint32 maxlen) {
  static int cur_stream_id = 0;
  STREAM result = NULL;

  result = &g_out[cur_stream_id];
  cur_stream_id = (cur_stream_id + 1) % STREAM_COUNT;


  if (maxlen > result->size) {
    result->data = (uint8 *) xrealloc(result->data, maxlen);
    result->size = maxlen;
  }

  result->p = result->data;
  result->end = result->data;   // + result->size;
  return result;
}

/* Send TCP transport data packet */
void tcp_send(STREAM s) {
  int length = s->end - s->data;
  int sent, total = 0;


  while (total < length) {
    sent = hydra_send(g_sock, (char *) (s->data + total), length - total, 0);
    if (sent <= 0) {
      if (sent == -1 && TCP_BLOCKS) {
        tcp_can_send(g_sock, 100);
        sent = 0;
      } else {
        if (g_sock && !login_result)
          error("send: %s\n", TCP_STRERROR);
        return;
      }
    }
    total += sent;
  }
}

/* Receive a message on the TCP layer */
STREAM tcp_recv(STREAM s, uint32 length) {
  uint32 new_length, end_offset, p_offset;
  int rcvd = 0;

  if (s == NULL) {
    /* read into "new" stream */
    g_in.data = (uint8 *) xmalloc(length);
    g_in.size = length;
    g_in.end = g_in.p = g_in.data;
    s = &g_in;
  } else {
    /* append to existing stream */
    new_length = (s->end - s->data) + length;
    if (new_length > s->size) {
      p_offset = s->p - s->data;
      end_offset = s->end - s->data;
//printf("length: %d, %p s->data, %p +%d s->p, %p +%d s->end, end-data %d, size %d\n", length, s->data, s->p, s->p - s->data, s->end, s->end - s->p, s->end - s->data, s->size);
      s->data = (uint8 *) xrealloc(s->data, new_length);
      s->size = new_length;
      s->p = s->data + p_offset;
      s->end = s->data + end_offset;
    }
  }


  while (length > 0) {
    rcvd = hydra_recv(g_sock, (char *) s->end, length);
    if (rcvd < 0) {
      if (rcvd == -1 && TCP_BLOCKS) {
        rcvd = 0;
      } else {
        //error("recv: %s\n", TCP_STRERROR);
        return NULL;
      }
    } else if (rcvd == 0) {
      error("Connection closed\n");
      return NULL;
    }
    s->end += rcvd;
    length -= rcvd;
  }


  return s;
}

char *tcp_get_address() {
  static char ipaddr[32];
  struct sockaddr_in sockaddr;
  socklen_t len = sizeof(sockaddr);

  if (getsockname(g_sock, (struct sockaddr *) &sockaddr, &len) == 0) {
    uint8 *ip = (uint8 *) & sockaddr.sin_addr;

    sprintf(ipaddr, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
  } else
    strcpy(ipaddr, "127.0.0.1");
  return ipaddr;
}

/* reset the state of the tcp layer */
void tcp_reset_state(void) {
  int i;

  g_sock = -1;                  /* reset socket */

  /* Clear the incoming stream */
  if (g_in.data != NULL)
    free(g_in.data);
  g_in.p = NULL;
  g_in.end = NULL;
  g_in.data = NULL;
  g_in.size = 0;
  g_in.iso_hdr = NULL;
  g_in.mcs_hdr = NULL;
  g_in.sec_hdr = NULL;
  g_in.rdp_hdr = NULL;
  g_in.channel_hdr = NULL;

  /* Clear the outgoing stream(s) */
  for (i = 0; i < STREAM_COUNT; i++) {
    if (g_out[i].data != NULL)
      free(g_out[i].data);
    g_out[i].p = NULL;
    g_out[i].end = NULL;
    g_out[i].data = NULL;
    g_out[i].size = 0;
    g_out[i].iso_hdr = NULL;
    g_out[i].mcs_hdr = NULL;
    g_out[i].sec_hdr = NULL;
    g_out[i].rdp_hdr = NULL;
    g_out[i].channel_hdr = NULL;
  }
}

uint16 g_mcs_userid;

/* Parse an ASN.1 BER header */
static BOOL ber_parse_header(STREAM s, int tagval, int *length) {
  int tag, len;


  if (tagval > 0xff) {
    in_uint16_be(s, tag);
  } else {
    in_uint8(s, tag);
  }

  if (tag != tagval) {
    error("expected tag %d, got %d\n", tagval, tag);
    return False;
  }

  in_uint8(s, len);

  if (len & 0x80) {
    len &= ~0x80;
    *length = 0;
    while (len--)
      next_be(s, *length);
  } else
    *length = len;

  return s_check(s);
}

/* Output an ASN.1 BER header */
static void ber_out_header(STREAM s, int tagval, int length) {


  if (tagval > 0xff) {
    out_uint16_be(s, tagval);
  } else {
    out_uint8(s, tagval);
  }

  if (length >= 0x80) {
    out_uint8(s, 0x82);
    out_uint16_be(s, length);
  } else
    out_uint8(s, length);
}

/* Output an ASN.1 BER integer */
static void ber_out_integer(STREAM s, int value) {
  ber_out_header(s, BER_TAG_INTEGER, 2);
  out_uint16_be(s, value);
}

/* Output a DOMAIN_PARAMS structure (ASN.1 BER) */
static void mcs_out_domain_params(STREAM s, int max_channels, int max_users, int max_tokens, int max_pdusize) {
  ber_out_header(s, MCS_TAG_DOMAIN_PARAMS, 32);
  ber_out_integer(s, max_channels);
  ber_out_integer(s, max_users);
  ber_out_integer(s, max_tokens);
  ber_out_integer(s, 1);        /* num_priorities */
  ber_out_integer(s, 0);        /* min_throughput */
  ber_out_integer(s, 1);        /* max_height */
  ber_out_integer(s, max_pdusize);
  ber_out_integer(s, 2);        /* ver_protocol */
}

/* Parse a DOMAIN_PARAMS structure (ASN.1 BER) */
static BOOL mcs_parse_domain_params(STREAM s) {
  int length = 0;

  ber_parse_header(s, MCS_TAG_DOMAIN_PARAMS, &length);
  in_uint8s(s, length);

  return s_check(s);
}

/* Send an MCS_CONNECT_INITIAL message (ASN.1 BER) */
static void mcs_send_connect_initial(STREAM mcs_data) {
  int datalen = mcs_data->end - mcs_data->data;
  int length = 9 + 3 * 34 + 4 + datalen;
  STREAM s;

  s = iso_init(length + 5);

  ber_out_header(s, MCS_CONNECT_INITIAL, length);
  ber_out_header(s, BER_TAG_OCTET_STRING, 1);   /* calling domain */
  out_uint8(s, 1);
  ber_out_header(s, BER_TAG_OCTET_STRING, 1);   /* called domain */
  out_uint8(s, 1);

  ber_out_header(s, BER_TAG_BOOLEAN, 1);
  out_uint8(s, 0xff);           /* upward flag */

  mcs_out_domain_params(s, 34, 2, 0, 0xffff);   /* target params */
  mcs_out_domain_params(s, 1, 1, 1, 0x420);     /* min params */
  mcs_out_domain_params(s, 0xffff, 0xfc17, 0xffff, 0xffff);     /* max params */

  ber_out_header(s, BER_TAG_OCTET_STRING, datalen);
  out_uint8p(s, mcs_data->data, datalen);

  s_mark_end(s);
  iso_send(s);
}

/* Expect a MCS_CONNECT_RESPONSE message (ASN.1 BER) */
static BOOL mcs_recv_connect_response(STREAM mcs_data) {
  uint8 result;
  int length = 0;
  STREAM s;

  s = iso_recv(NULL);
  if (s == NULL)
    return False;

  ber_parse_header(s, MCS_CONNECT_RESPONSE, &length);

  ber_parse_header(s, BER_TAG_RESULT, &length);
  in_uint8(s, result);
  if (result != 0) {
    error("MCS connect: %d\n", result);
    return False;
  }

  ber_parse_header(s, BER_TAG_INTEGER, &length);
  in_uint8s(s, length);         /* connect id */
  mcs_parse_domain_params(s);

  ber_parse_header(s, BER_TAG_OCTET_STRING, &length);

  sec_process_mcs_data(s);
  /*
     if (length > mcs_data->size)
     {
     error("MCS data length %d, expected %d\n", length,
     mcs_data->size);
     length = mcs_data->size;
     }

     in_uint8a(s, mcs_data->data, length);
     mcs_data->p = mcs_data->data;
     mcs_data->end = mcs_data->data + length;
   */
  return s_check_end(s);
}

/* Send an EDrq message (ASN.1 PER) */
static void mcs_send_edrq(void) {
  STREAM s;

  s = iso_init(5);

  out_uint8(s, (MCS_EDRQ << 2));
  out_uint16_be(s, 1);          /* height */
  out_uint16_be(s, 1);          /* interval */

  s_mark_end(s);
  iso_send(s);
}

/* Send an AUrq message (ASN.1 PER) */
static void mcs_send_aurq(void) {
  STREAM s;

  s = iso_init(1);

  out_uint8(s, (MCS_AURQ << 2));

  s_mark_end(s);
  iso_send(s);
}

/* Expect a AUcf message (ASN.1 PER) */
static BOOL mcs_recv_aucf(uint16 * mcs_userid) {
  uint8 opcode, result;
  STREAM s;

  s = iso_recv(NULL);
  if (s == NULL)
    return False;

  in_uint8(s, opcode);
  if ((opcode >> 2) != MCS_AUCF) {
    error("expected AUcf, got %d\n", opcode);
    return False;
  }

  in_uint8(s, result);
  if (result != 0) {
    error("AUrq: %d\n", result);
    return False;
  }

  if (opcode & 2)
    in_uint16_be(s, *mcs_userid);

  return s_check_end(s);
}

/* Send a CJrq message (ASN.1 PER) */
static void mcs_send_cjrq(uint16 chanid) {
  STREAM s;

  DEBUG_RDP5(("Sending CJRQ for channel #%d\n", chanid));

  s = iso_init(5);

  out_uint8(s, (MCS_CJRQ << 2));
  out_uint16_be(s, g_mcs_userid);
  out_uint16_be(s, chanid);

  s_mark_end(s);
  iso_send(s);
}

/* Expect a CJcf message (ASN.1 PER) */
static BOOL mcs_recv_cjcf(void) {
  uint8 opcode, result;
  STREAM s;

  s = iso_recv(NULL);
  if (s == NULL)
    return False;

  in_uint8(s, opcode);
  if ((opcode >> 2) != MCS_CJCF) {
    error("expected CJcf, got %d\n", opcode);
    return False;
  }

  in_uint8(s, result);
  if (result != 0) {
    error("CJrq: %d\n", result);
    return False;
  }

  in_uint8s(s, 4);              /* mcs_userid, req_chanid */
  if (opcode & 2)
    in_uint8s(s, 2);            /* join_chanid */

  return s_check_end(s);
}

/* Initialise an MCS transport data packet */
STREAM mcs_init(int length) {
  STREAM s;

  s = iso_init(length + 8);
  s_push_layer(s, mcs_hdr, 8);

  return s;
}

/* Send an MCS transport data packet to a specific channel */
void mcs_send_to_channel(STREAM s, uint16 channel) {
  uint16 length;

  s_pop_layer(s, mcs_hdr);
  length = s->end - s->p - 8;
  length |= 0x8000;

  out_uint8(s, (MCS_SDRQ << 2));
  out_uint16_be(s, g_mcs_userid);
  out_uint16_be(s, channel);
  out_uint8(s, 0x70);           /* flags */
  out_uint16_be(s, length);

  iso_send(s);
}

/* Send an MCS transport data packet to the global channel */
void mcs_send(STREAM s) {
  mcs_send_to_channel(s, MCS_GLOBAL_CHANNEL);
}

/* Receive an MCS transport data packet */
STREAM mcs_recv(uint16 * channel, uint8 * rdpver) {
  uint8 opcode, appid, length;
  STREAM s;

  s = iso_recv(rdpver);
  if (s == NULL)
    return NULL;
  if (rdpver != NULL)
    if (*rdpver != 3)
      return s;
  in_uint8(s, opcode);
  appid = opcode >> 2;
  if (appid != MCS_SDIN) {
    if (appid != MCS_DPUM) {
      error("expected data, got %d\n", opcode);
    }
    return NULL;
  }
  in_uint8s(s, 2);              /* userid */
  in_uint16_be(s, *channel);
  in_uint8s(s, 1);              /* flags */
  in_uint8(s, length);
  if (length & 0x80)
    in_uint8s(s, 1);            /* second byte of length */
  return s;
}

BOOL mcs_connect(char *server, STREAM mcs_data, char *username, BOOL reconnect) {
  if (!iso_connect(server, username, reconnect))
    return False;
  mcs_send_connect_initial(mcs_data);
  if (!mcs_recv_connect_response(mcs_data))
    goto error;
  mcs_send_edrq();
  mcs_send_aurq();
  if (!mcs_recv_aucf(&g_mcs_userid))
    goto error;
  mcs_send_cjrq(g_mcs_userid + MCS_USERCHANNEL_BASE);
  if (!mcs_recv_cjcf())
    goto error;
  mcs_send_cjrq(MCS_GLOBAL_CHANNEL);
  if (!mcs_recv_cjcf())
    goto error;
  return True;
error:
  iso_disconnect();
  return False;
}

/* Disconnect from the MCS layer */
void mcs_disconnect(void) {
  iso_disconnect();
}

/* reset the state of the mcs layer */
void mcs_reset_state(void) {
  g_mcs_userid = 0;
  iso_reset_state();
}

/* Send a self-contained ISO PDU */
static void iso_send_msg(uint8 code) {
  STREAM s;

  s = tcp_init(11);

  out_uint8(s, 3);              /* version */
  out_uint8(s, 0);              /* reserved */
  out_uint16_be(s, 11);         /* length */

  out_uint8(s, 6);              /* hdrlen */
  out_uint8(s, code);
  out_uint16(s, 0);             /* dst_ref */
  out_uint16(s, 0);             /* src_ref */
  out_uint8(s, 0);              /* class */

  s_mark_end(s);
  tcp_send(s);
}

static void iso_send_connection_request(char *username) {
  STREAM s;
  int length = 30 + strlen(username);

  s = tcp_init(length);

  out_uint8(s, 3);              /* version */
  out_uint8(s, 0);              /* reserved */
  out_uint16_be(s, length);     /* length */

  out_uint8(s, length - 5);     /* hdrlen */
  out_uint8(s, ISO_PDU_CR);
  out_uint16(s, 0);             /* dst_ref */
  out_uint16(s, 0);             /* src_ref */
  out_uint8(s, 0);              /* class */

  out_uint8p(s, "Cookie: mstshash=", strlen("Cookie: mstshash="));
  out_uint8p(s, username, strlen(username));

  out_uint8(s, 0x0d);           /* Unknown */
  out_uint8(s, 0x0a);           /* Unknown */

  s_mark_end(s);
  tcp_send(s);
}

/* Send a single input event fast JL, this is required for win8 */
void rdp_send_fast_input_kbd(uint32 time, uint16 flags, uint16 param1) {
  STREAM s;
  uint8 fast_flags = 0;
  uint8 len = 4;

  fast_flags |= (flags & RDP_KEYRELEASE) ? FASTPATH_INPUT_KBDFLAGS_RELEASE : 0;
  s = tcp_init(len);
  out_uint8(s, (1 << 2));       //one event 
  out_uint8(s, len);
  out_uint8(s, fast_flags | (FASTPATH_INPUT_EVENT_SCANCODE << 5));
  out_uint8(s, param1);
  s_mark_end(s);
  tcp_send(s);
}

/* Send a single input event fast JL, this is required for win8 */
void rdp_send_fast_input_mouse(uint32 time, uint16 flags, uint16 param1, uint16 param2) {
  STREAM s;
  uint8 len = 9;

  s = tcp_init(len);
  out_uint8(s, (1 << 2));       //one event 
  out_uint8(s, len);
  out_uint8(s, (FASTPATH_INPUT_EVENT_MOUSE << 5));
  out_uint16(s, flags);
  out_uint16(s, param1);
  out_uint16(s, param2);
  s_mark_end(s);
  tcp_send(s);
}


/* Receive a message on the ISO layer, return code */
static STREAM iso_recv_msg(uint8 * code, uint8 * rdpver) {
  STREAM s;
  uint16 length;
  uint8 version;

  s = tcp_recv(NULL, 4);
  if (s == NULL)
    return NULL;
  in_uint8(s, version);
  if (rdpver != NULL)
    *rdpver = version;
  if (version == 3) {
    in_uint8s(s, 1);            /* pad */
    in_uint16_be(s, length);
  } else {
    in_uint8(s, length);
    if (length & 0x80) {
      length &= ~0x80;
      next_be(s, length);
    }
  }
  if (length < 5) {
    error("Bad packet header\n");
    return NULL;
  }
  s = tcp_recv(s, length - 4);
  if (s == NULL)
    return NULL;
  if (version != 3)
    return s;
  in_uint8s(s, 1);              /* hdrlen */
  in_uint8(s, *code);
  if (*code == ISO_PDU_DT) {
    in_uint8s(s, 1);            /* eot */
    return s;
  }
  in_uint8s(s, 5);              /* dst_ref, src_ref, class */
  return s;
}

/* Initialise ISO transport data packet */
STREAM iso_init(int length) {
  STREAM s;

  s = tcp_init(length + 7);
  s_push_layer(s, iso_hdr, 7);

  return s;
}

/* Send an ISO data PDU */
void iso_send(STREAM s) {
  uint16 length;

  s_pop_layer(s, iso_hdr);
  length = s->end - s->p;

  out_uint8(s, 3);              /* version */
  out_uint8(s, 0);              /* reserved */
  out_uint16_be(s, length);

  out_uint8(s, 2);              /* hdrlen */
  out_uint8(s, ISO_PDU_DT);     /* code */
  out_uint8(s, 0x80);           /* eot */

  tcp_send(s);
}

/* Receive ISO transport data packet */
STREAM iso_recv(uint8 * rdpver) {
  STREAM s;
  uint8 code = 0;

  s = iso_recv_msg(&code, rdpver);
  if (s == NULL)
    return NULL;
  if (rdpver != NULL)
    if (*rdpver != 3)
      return s;
  if (code != ISO_PDU_DT) {
    error("expected DT, got 0x%x\n", code);
    return NULL;
  }
  return s;
}

/* Establish a connection up to the ISO layer */
BOOL iso_connect(char *server, char *username, BOOL reconnect) {
  uint8 code = 0;

  if (reconnect) {
    iso_send_msg(ISO_PDU_CR);
  } else {
    iso_send_connection_request(username);
  }
  if (iso_recv_msg(&code, NULL) == NULL) {
    return False;
  }
  if (code != ISO_PDU_CC) {
    error("expected CC, got 0x%x\n", code);
    hydra_disconnect(g_sock);
    return False;
  }

  return True;
}

/* Disconnect from the ISO layer */
void iso_disconnect(void) {
  iso_send_msg(ISO_PDU_DR);
  g_sock = hydra_disconnect(g_sock);
}

/* reset the state to support reconnecting */
void iso_reset_state(void) {
  tcp_reset_state();
}

static int g_rc4_key_len;
static SSL_RC4 g_rc4_decrypt_key;
static SSL_RC4 g_rc4_encrypt_key;
static uint32 g_server_public_key_len;

static uint8 g_sec_sign_key[16];
static uint8 g_sec_decrypt_key[16];
static uint8 g_sec_encrypt_key[16];
static uint8 g_sec_decrypt_update_key[16];
static uint8 g_sec_encrypt_update_key[16];
static uint8 g_sec_crypted_random[SEC_MAX_MODULUS_SIZE];

uint16 g_server_rdp_version = 0;

/* These values must be available to reset state - Session Directory */
static int g_sec_encrypt_use_count = 0;
static int g_sec_decrypt_use_count = 0;


void ssl_sha1_init(SSL_SHA1 * sha1) {
  SHA1_Init(sha1);
}

void ssl_sha1_update(SSL_SHA1 * sha1, uint8 * data, uint32 len) {
  SHA1_Update(sha1, data, len);
}

void ssl_sha1_final(SSL_SHA1 * sha1, uint8 * out_data) {
  SHA1_Final(out_data, sha1);
}

void ssl_md5_init(SSL_MD5 * md5) {
  MD5_Init(md5);
}

void ssl_md5_update(SSL_MD5 * md5, uint8 * data, uint32 len) {
  MD5_Update(md5, data, len);
}

void ssl_md5_final(SSL_MD5 * md5, uint8 * out_data) {
  MD5_Final(out_data, md5);
}

void ssl_rc4_set_key(SSL_RC4 * rc4, uint8 * key, uint32 len) {
  RC4_set_key(rc4, len, key);
}

void ssl_rc4_crypt(SSL_RC4 * rc4, uint8 * in_data, uint8 * out_data, uint32 len) {
  RC4(rc4, len, in_data, out_data);
}

static void reverse(uint8 * p, int len) {
  int i, j;
  uint8 temp;

  for (i = 0, j = len - 1; i < j; i++, j--) {
    temp = p[i];
    p[i] = p[j];
    p[j] = temp;
  }
}

void ssl_rsa_encrypt(uint8 * out, uint8 * in, int len, uint32 modulus_size, uint8 * modulus, uint8 * exponent) {
  BN_CTX *ctx;
  BIGNUM mod, exp, x, y;
  uint8 inr[SEC_MAX_MODULUS_SIZE];
  int outlen;

  reverse(modulus, modulus_size);
  reverse(exponent, SEC_EXPONENT_SIZE);
  memcpy(inr, in, len);
  reverse(inr, len);

  ctx = BN_CTX_new();
  BN_init(&mod);
  BN_init(&exp);
  BN_init(&x);
  BN_init(&y);

  BN_bin2bn(modulus, modulus_size, &mod);
  BN_bin2bn(exponent, SEC_EXPONENT_SIZE, &exp);
  BN_bin2bn(inr, len, &x);
  BN_mod_exp(&y, &x, &exp, &mod, ctx);
  outlen = BN_bn2bin(&y, out);
  reverse(out, outlen);
  if (outlen < (int) modulus_size)
    memset(out + outlen, 0, modulus_size - outlen);

  BN_free(&y);
  BN_clear_free(&x);
  BN_free(&exp);
  BN_free(&mod);
  BN_CTX_free(ctx);
}

/* returns newly allocated SSL_CERT or NULL */
SSL_CERT *ssl_cert_read(uint8 * data, uint32 len) {
  /* this will move the data pointer but we don't care, we don't use it again */
  return d2i_X509(NULL, (D2I_X509_CONST unsigned char **) &data, len);
}

void ssl_cert_free(SSL_CERT * cert) {
  X509_free(cert);
}

/* returns newly allocated SSL_RKEY or NULL */
SSL_RKEY *ssl_cert_to_rkey(SSL_CERT * cert, uint32 * key_len) {
  EVP_PKEY *epk = NULL;
  SSL_RKEY *lkey;
  int nid;

  /* By some reason, Microsoft sets the OID of the Public RSA key to
     the oid for "MD5 with RSA Encryption" instead of "RSA Encryption"

     Kudos to Richard Levitte for the following (. intiutive .) 
     lines of code that resets the OID and let's us extract the key. */
  nid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
  if ((nid == NID_md5WithRSAEncryption) || (nid == NID_shaWithRSAEncryption)) {
    DEBUG_RDP5(("Re-setting algorithm type to RSA in server certificate\n"));
    ASN1_OBJECT_free(cert->cert_info->key->algor->algorithm);
    cert->cert_info->key->algor->algorithm = OBJ_nid2obj(NID_rsaEncryption);
  }
  epk = X509_get_pubkey(cert);
  if (NULL == epk) {
    error("Failed to extract public key from certificate\n");
    return NULL;
  }

  lkey = RSAPublicKey_dup(EVP_PKEY_get1_RSA(epk));
  EVP_PKEY_free(epk);
  *key_len = RSA_size(lkey);
  return lkey;
}

int ssl_cert_print_fp(FILE * fp, SSL_CERT * cert) {
  return X509_print_fp(fp, cert);
}

void ssl_rkey_free(SSL_RKEY * rkey) {
  RSA_free(rkey);
}

/* returns error */
int ssl_rkey_get_exp_mod(SSL_RKEY * rkey, uint8 * exponent, uint32 max_exp_len, uint8 * modulus, uint32 max_mod_len) {
  int len;

  if ((BN_num_bytes(rkey->e) > (int) max_exp_len) || (BN_num_bytes(rkey->n) > (int) max_mod_len)) {
    return 1;
  }
  len = BN_bn2bin(rkey->e, exponent);
  reverse(exponent, len);
  len = BN_bn2bin(rkey->n, modulus);
  reverse(modulus, len);
  return 0;
}

/* returns boolean */
BOOL ssl_sig_ok(uint8 * exponent, uint32 exp_len, uint8 * modulus, uint32 mod_len, uint8 * signature, uint32 sig_len) {
  return True;
}


void ssl_hmac_md5(const void *key, int key_len, const unsigned char *msg, int msg_len, unsigned char *md) {
  HMAC_CTX ctx;

  HMAC_CTX_init(&ctx);
  HMAC(EVP_md5(), key, key_len, msg, msg_len, md, NULL);
  HMAC_CTX_cleanup(&ctx);
}


/*
 * I believe this is based on SSLv3 with the following differences:
 *  MAC algorithm (5.2.3.1) uses only 32-bit length in place of seq_num/type/length fields
 *  MAC algorithm uses SHA1 and MD5 for the two hash functions instead of one or other
 *  key_block algorithm (6.2.2) uses 'X', 'YY', 'ZZZ' instead of 'A', 'BB', 'CCC'
 *  key_block partitioning is different (16 bytes each: MAC secret, decrypt key, encrypt key)
 *  encryption/decryption keys updated every 4096 packets
 * See http://wp.netscape.com/eng/ssl3/draft302.txt
 */

/*
 * 48-byte transformation used to generate master secret (6.1) and key material (6.2.2).
 * Both SHA1 and MD5 algorithms are used.
 */
void sec_hash_48(uint8 * out, uint8 * in, uint8 * salt1, uint8 * salt2, uint8 salt) {
  uint8 shasig[20];
  uint8 pad[4];
  SSL_SHA1 sha1;
  SSL_MD5 md5;
  int i;

  for (i = 0; i < 3; i++) {
    memset(pad, salt + i, i + 1);

    ssl_sha1_init(&sha1);
    ssl_sha1_update(&sha1, pad, i + 1);
    ssl_sha1_update(&sha1, in, 48);
    ssl_sha1_update(&sha1, salt1, 32);
    ssl_sha1_update(&sha1, salt2, 32);
    ssl_sha1_final(&sha1, shasig);

    ssl_md5_init(&md5);
    ssl_md5_update(&md5, in, 48);
    ssl_md5_update(&md5, shasig, 20);
    ssl_md5_final(&md5, &out[i * 16]);
  }
}

/*
 * 16-byte transformation used to generate export keys (6.2.2).
 */
void sec_hash_16(uint8 * out, uint8 * in, uint8 * salt1, uint8 * salt2) {
  SSL_MD5 md5;

  ssl_md5_init(&md5);
  ssl_md5_update(&md5, in, 16);
  ssl_md5_update(&md5, salt1, 32);
  ssl_md5_update(&md5, salt2, 32);
  ssl_md5_final(&md5, out);
}

/* Reduce key entropy from 64 to 40 bits */
static void sec_make_40bit(uint8 * key) {
  key[0] = 0xd1;
  key[1] = 0x26;
  key[2] = 0x9e;
}

/* Generate encryption keys given client and server randoms */
static void sec_generate_keys(uint8 * client_random, uint8 * server_random, int rc4_key_size) {
  uint8 pre_master_secret[48];
  uint8 master_secret[48];
  uint8 key_block[48];

  /* Construct pre-master secret */
  memcpy(pre_master_secret, client_random, 24);
  memcpy(pre_master_secret + 24, server_random, 24);

  /* Generate master secret and then key material */
  sec_hash_48(master_secret, pre_master_secret, client_random, server_random, 'A');
  sec_hash_48(key_block, master_secret, client_random, server_random, 'X');

  /* First 16 bytes of key material is MAC secret */
  memcpy(g_sec_sign_key, key_block, 16);

  /* Generate export keys from next two blocks of 16 bytes */
  sec_hash_16(g_sec_decrypt_key, &key_block[16], client_random, server_random);
  sec_hash_16(g_sec_encrypt_key, &key_block[32], client_random, server_random);

  if (rc4_key_size == 1) {
    DEBUG(("40-bit encryption enabled\n"));
    sec_make_40bit(g_sec_sign_key);
    sec_make_40bit(g_sec_decrypt_key);
    sec_make_40bit(g_sec_encrypt_key);
    g_rc4_key_len = 8;
  } else {
    DEBUG(("rc_4_key_size == %d, 128-bit encryption enabled\n", rc4_key_size));
    g_rc4_key_len = 16;
  }

  /* Save initial RC4 keys as update keys */
  memcpy(g_sec_decrypt_update_key, g_sec_decrypt_key, 16);
  memcpy(g_sec_encrypt_update_key, g_sec_encrypt_key, 16);

  /* Initialise RC4 state arrays */
  ssl_rc4_set_key(&g_rc4_decrypt_key, g_sec_decrypt_key, g_rc4_key_len);
  ssl_rc4_set_key(&g_rc4_encrypt_key, g_sec_encrypt_key, g_rc4_key_len);
}

static uint8 pad_54[40] = {
  54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54,
  54, 54, 54,
  54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54,
  54, 54, 54
};

static uint8 pad_92[48] = {
  92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92,
  92, 92, 92, 92, 92, 92, 92,
  92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92,
  92, 92, 92, 92, 92, 92, 92
};

/* Output a uint32 into a buffer (little-endian) */
void buf_out_uint32(uint8 * buffer, uint32 value) {
  buffer[0] = (value) & 0xff;
  buffer[1] = (value >> 8) & 0xff;
  buffer[2] = (value >> 16) & 0xff;
  buffer[3] = (value >> 24) & 0xff;
}

/* Generate a MAC hash (5.2.3.1), using a combination of SHA1 and MD5 */
void sec_sign(uint8 * signature, int siglen, uint8 * session_key, int keylen, uint8 * data, int datalen) {
  uint8 shasig[20];
  uint8 md5sig[16];
  uint8 lenhdr[4];
  SSL_SHA1 sha1;
  SSL_MD5 md5;

  buf_out_uint32(lenhdr, datalen);

  ssl_sha1_init(&sha1);
  ssl_sha1_update(&sha1, session_key, keylen);
  ssl_sha1_update(&sha1, pad_54, 40);
  ssl_sha1_update(&sha1, lenhdr, 4);
  ssl_sha1_update(&sha1, data, datalen);
  ssl_sha1_final(&sha1, shasig);

  ssl_md5_init(&md5);
  ssl_md5_update(&md5, session_key, keylen);
  ssl_md5_update(&md5, pad_92, 48);
  ssl_md5_update(&md5, shasig, 20);
  ssl_md5_final(&md5, md5sig);

  memcpy(signature, md5sig, siglen);
}

/* Update an encryption key */
static void sec_update(uint8 * key, uint8 * update_key) {
  uint8 shasig[20];
  SSL_SHA1 sha1;
  SSL_MD5 md5;
  SSL_RC4 update;

  ssl_sha1_init(&sha1);
  ssl_sha1_update(&sha1, update_key, g_rc4_key_len);
  ssl_sha1_update(&sha1, pad_54, 40);
  ssl_sha1_update(&sha1, key, g_rc4_key_len);
  ssl_sha1_final(&sha1, shasig);

  ssl_md5_init(&md5);
  ssl_md5_update(&md5, update_key, g_rc4_key_len);
  ssl_md5_update(&md5, pad_92, 48);
  ssl_md5_update(&md5, shasig, 20);
  ssl_md5_final(&md5, key);

  ssl_rc4_set_key(&update, key, g_rc4_key_len);
  ssl_rc4_crypt(&update, key, key, g_rc4_key_len);

  if (g_rc4_key_len == 8)
    sec_make_40bit(key);
}

/* Encrypt data using RC4 */
static void sec_encrypt(uint8 * data, int length) {
  if (g_sec_encrypt_use_count == 4096) {
    sec_update(g_sec_encrypt_key, g_sec_encrypt_update_key);
    ssl_rc4_set_key(&g_rc4_encrypt_key, g_sec_encrypt_key, g_rc4_key_len);
    g_sec_encrypt_use_count = 0;
  }

  ssl_rc4_crypt(&g_rc4_encrypt_key, data, data, length);
  g_sec_encrypt_use_count++;
}

/* Decrypt data using RC4 */
void sec_decrypt(uint8 * data, int length) {
  if (g_sec_decrypt_use_count == 4096) {
    sec_update(g_sec_decrypt_key, g_sec_decrypt_update_key);
    ssl_rc4_set_key(&g_rc4_decrypt_key, g_sec_decrypt_key, g_rc4_key_len);
    g_sec_decrypt_use_count = 0;
  }

  ssl_rc4_crypt(&g_rc4_decrypt_key, data, data, length);
  g_sec_decrypt_use_count++;
}

/* Perform an RSA public key encryption operation */
static void sec_rsa_encrypt(uint8 * out, uint8 * in, int len, uint32 modulus_size, uint8 * modulus, uint8 * exponent) {
  ssl_rsa_encrypt(out, in, len, modulus_size, modulus, exponent);
}

/* Initialise secure transport packet */
STREAM sec_init(uint32 flags, int maxlen) {
  int hdrlen;
  STREAM s;

//      if (!g_licence_issued)
  hdrlen = (flags & SEC_ENCRYPT) ? 12 : 4;
//      else

//              hdrlen = (flags & SEC_ENCRYPT) ? 12 : 0;
  s = mcs_init(maxlen + hdrlen);
  s_push_layer(s, sec_hdr, hdrlen);

  return s;
}

/* Transmit secure transport packet over specified channel */
void sec_send_to_channel(STREAM s, uint32 flags, uint16 channel) {
  int datalen;

  s_pop_layer(s, sec_hdr);
  out_uint32_le(s, flags);

  if (flags & SEC_ENCRYPT) {
    flags &= ~SEC_ENCRYPT;
    datalen = s->end - s->p - 8;

    sec_sign(s->p, 8, g_sec_sign_key, g_rc4_key_len, s->p + 8, datalen);
    sec_encrypt(s->p + 8, datalen);
  }

  mcs_send_to_channel(s, channel);
}

/* Transmit secure transport packet */

void sec_send(STREAM s, uint32 flags) {
  sec_send_to_channel(s, flags, MCS_GLOBAL_CHANNEL);
}


/* Transfer the client random to the server */
static void sec_establish_key(void) {
  uint32 length = g_server_public_key_len + SEC_PADDING_SIZE;
  uint32 flags = SEC_CLIENT_RANDOM;
  STREAM s;

  s = sec_init(flags, length + 4);

  out_uint32_le(s, length);
  out_uint8p(s, g_sec_crypted_random, g_server_public_key_len);
  out_uint8s(s, SEC_PADDING_SIZE);

  s_mark_end(s);
  sec_send(s, flags);
}

/* Output a string in Unicode */
void rdp_out_unistr(STREAM s, char *string, int len) {
  int i = 0, j = 0;

  len += 2;
  while (i < len) {
    s->p[i++] = string[j++];
    s->p[i++] = 0;
  }
  s->p += len;
}

/* Output connect initial data blob */
static void sec_out_mcs_data(STREAM s) {
  char *g_hostname = "hydra";
  int hostlen = 2 * strlen(g_hostname);
  int length = 158 + 76 + 12 + 4;

/*
	if (g_num_channels > 0)
		length += g_num_channels * 12 + 8;
*/
  if (hostlen > 30)
    hostlen = 30;

  /* Generic Conference Control (T.124) ConferenceCreateRequest */
  out_uint16_be(s, 5);
  out_uint16_be(s, 0x14);
  out_uint8(s, 0x7c);
  out_uint16_be(s, 1);

  out_uint16_be(s, (length | 0x8000));  /* remaining length */

  out_uint16_be(s, 8);          /* length? */
  out_uint16_be(s, 16);
  out_uint8(s, 0);
  out_uint16_le(s, 0xc001);
  out_uint8(s, 0);

  out_uint32_le(s, 0x61637544); /* OEM ID: "Duca", as in Ducati. */
  out_uint16_be(s, ((length - 14) | 0x8000));   /* remaining length */

  /* Client information */
  out_uint16_le(s, SEC_TAG_CLI_INFO);
  out_uint16_le(s, 212);        /* length */
  out_uint16_le(s, g_use_rdp5 ? 4 : 1); /* RDP version. 1 == RDP4, 4 == RDP5. */
  out_uint16_le(s, 8);
  out_uint16_le(s, 800);
  out_uint16_le(s, 600);
  out_uint16_le(s, 0xca01);
  out_uint16_le(s, 0xaa03);
  out_uint32_le(s, 0x409);
  out_uint32_le(s, 2600);       /* Client build. We are now 2600 compatible :-) */

  /* Unicode name of client, padded to 32 bytes */
  rdp_out_unistr(s, g_hostname, hostlen);
  out_uint8s(s, 30 - hostlen);

  /* See
     http://msdn.microsoft.com/library/default.asp?url=/library/en-us/wceddk40/html/cxtsksupportingremotedesktopprotocol.asp */
  out_uint32_le(s, 0x4);
  out_uint32_le(s, 0x0);
  out_uint32_le(s, 0xc);
  out_uint8s(s, 64);            /* reserved? 4 + 12 doublewords */
  out_uint16_le(s, 0xca01);     /* colour depth? */
  out_uint16_le(s, 1);

  out_uint32(s, 0);
  out_uint8(s, g_server_depth);
  out_uint16_le(s, 0x0700);
  out_uint8(s, 0);
  out_uint32_le(s, 1);
  out_uint8s(s, 64);            /* End of client info */

  out_uint16_le(s, SEC_TAG_CLI_4);
  out_uint16_le(s, 12);
  out_uint32_le(s, g_console_session ? 0xb : 9);
  out_uint32(s, 0);

  /* Client encryption settings */
  out_uint16_le(s, SEC_TAG_CLI_CRYPT);
  out_uint16_le(s, 12);         /* length */
  out_uint32_le(s, g_encryption ? 0x3 : 0);     /* encryption supported, 128-bit supported */
  out_uint32(s, 0);             /* Unknown */

/*
	DEBUG_RDP5(("g_num_channels is %d\n", g_num_channels));
	if (g_num_channels > 0)
	{
		out_uint16_le(s, SEC_TAG_CLI_CHANNELS);
		out_uint16_le(s, g_num_channels * 12 + 8); //  length 
		out_uint32_le(s, g_num_channels); 	// number of virtual channels 
		for (i = 0; i < g_num_channels; i++)
		{
			DEBUG_RDP5(("Requesting channel %s\n", g_channels[i].name));
			out_uint8a(s, g_channels[i].name, 8);
			out_uint32_be(s, g_channels[i].flags);
		}
	}
*/
  s_mark_end(s);
}

/* Parse a public key structure */
static BOOL sec_parse_public_key(STREAM s, uint8 * modulus, uint8 * exponent) {
  uint32 magic, modulus_len;

  in_uint32_le(s, magic);

  if (magic != SEC_RSA_MAGIC) {
    error("RSA magic 0x%x\n", magic);
    return False;
  }

  in_uint32_le(s, modulus_len);
  modulus_len -= SEC_PADDING_SIZE;
  if ((modulus_len < SEC_MODULUS_SIZE) || (modulus_len > SEC_MAX_MODULUS_SIZE)) {
    error("Bad server public key size (%u bits)\n", modulus_len * 8);
    return False;
  }

  in_uint8s(s, 8);              /* modulus_bits, unknown */
  in_uint8a(s, exponent, SEC_EXPONENT_SIZE);
  in_uint8a(s, modulus, modulus_len);
  in_uint8s(s, SEC_PADDING_SIZE);
  g_server_public_key_len = modulus_len;

  return s_check(s);
}

/* Parse a public signature structure */
static BOOL sec_parse_public_sig(STREAM s, uint32 len, uint8 * modulus, uint8 * exponent) {
  uint8 signature[SEC_MAX_MODULUS_SIZE];
  uint32 sig_len;

  if (len != 72) {
    return True;
  }
  memset(signature, 0, sizeof(signature));
  sig_len = len - 8;
  in_uint8a(s, signature, sig_len);
  return ssl_sig_ok(exponent, SEC_EXPONENT_SIZE, modulus, g_server_public_key_len, signature, sig_len);
}

/* Parse a crypto information structure */
static BOOL sec_parse_crypt_info(STREAM s, uint32 * rc4_key_size, uint8 ** server_random, uint8 * modulus, uint8 * exponent) {
  uint32 crypt_level, random_len, rsa_info_len;
  uint32 cacert_len, cert_len, flags;
  SSL_CERT *cacert, *server_cert;
  SSL_RKEY *server_public_key;
  uint16 tag, length;
  uint8 *next_tag, *end;

  in_uint32_le(s, *rc4_key_size);       /* 1 = 40-bit, 2 = 128-bit */
  in_uint32_le(s, crypt_level); /* 1 = low, 2 = medium, 3 = high */
  if (crypt_level == 0)         /* no encryption */
    return False;
  in_uint32_le(s, random_len);
  in_uint32_le(s, rsa_info_len);

  if (random_len != SEC_RANDOM_SIZE) {
    error("random len %d, expected %d\n", random_len, SEC_RANDOM_SIZE);
    return False;
  }

  in_uint8p(s, *server_random, random_len);

  /* RSA info */
  end = s->p + rsa_info_len;
  if (end > s->end)
    return False;

  in_uint32_le(s, flags);       /* 1 = RDP4-style, 0x80000002 = X.509 */
  if (flags & 1) {
    DEBUG_RDP5(("We're going for the RDP4-style encryption\n"));
    in_uint8s(s, 8);            /* unknown */

    while (s->p < end) {
      in_uint16_le(s, tag);
      in_uint16_le(s, length);

      next_tag = s->p + length;

      switch (tag) {
      case SEC_TAG_PUBKEY:
        if (!sec_parse_public_key(s, modulus, exponent))
          return False;
        DEBUG_RDP5(("Got Public key, RDP4-style\n"));

        break;

      case SEC_TAG_KEYSIG:
        if (!sec_parse_public_sig(s, length, modulus, exponent))
          return False;
        break;

      default:
        unimpl("crypt tag 0x%x\n", tag);
      }

      s->p = next_tag;
    }
  } else {
    uint32 certcount;

    DEBUG_RDP5(("We're going for the RDP5-style encryption\n"));
    in_uint32_le(s, certcount); /* Number of certificates */
    if (certcount < 2) {
      error("Server didn't send enough X509 certificates\n");
      return False;
    }
    for (; certcount > 2; certcount--) {        /* ignore all the certificates between the root and the signing CA */
      uint32 ignorelen;
      SSL_CERT *ignorecert;

      DEBUG_RDP5(("Ignored certs left: %d\n", certcount));
      in_uint32_le(s, ignorelen);
      DEBUG_RDP5(("Ignored Certificate length is %d\n", ignorelen));
      ignorecert = ssl_cert_read(s->p, ignorelen);
      in_uint8s(s, ignorelen);
      if (ignorecert == NULL) { /* XXX: error out? */
        DEBUG_RDP5(("got a bad cert: this will probably screw up the rest of the communication\n"));
      }
#ifdef WITH_DEBUG_RDP5
      DEBUG_RDP5(("cert #%d (ignored):\n", certcount));
      ssl_cert_print_fp(stdout, ignorecert);
#endif
    }
    /* Do da funky X.509 stuffy

       "How did I find out about this?  I looked up and saw a
       bright light and when I came to I had a scar on my forehead
       and knew about X.500"
       - Peter Gutman in a early version of 
       http://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt
     */
    in_uint32_le(s, cacert_len);
    DEBUG_RDP5(("CA Certificate length is %d\n", cacert_len));
    cacert = ssl_cert_read(s->p, cacert_len);
    in_uint8s(s, cacert_len);
    if (NULL == cacert) {
      error("Couldn't load CA Certificate from server\n");
      return False;
    }
    in_uint32_le(s, cert_len);
    DEBUG_RDP5(("Certificate length is %d\n", cert_len));
    server_cert = ssl_cert_read(s->p, cert_len);
    in_uint8s(s, cert_len);
    if (NULL == server_cert) {
      ssl_cert_free(cacert);
      error("Couldn't load Certificate from server\n");
      return False;
    }
    ssl_cert_free(cacert);
    in_uint8s(s, 16);           /* Padding */
    server_public_key = ssl_cert_to_rkey(server_cert, &g_server_public_key_len);
    if (NULL == server_public_key) {
      DEBUG_RDP5(("Didn't parse X509 correctly\n"));
      ssl_cert_free(server_cert);
      return False;
    }
    ssl_cert_free(server_cert);
    if ((g_server_public_key_len < SEC_MODULUS_SIZE) || (g_server_public_key_len > SEC_MAX_MODULUS_SIZE)) {
      error("Bad server public key size (%u bits)\n", g_server_public_key_len * 8);
      ssl_rkey_free(server_public_key);
      return False;
    }
    if (ssl_rkey_get_exp_mod(server_public_key, exponent, SEC_EXPONENT_SIZE, modulus, SEC_MAX_MODULUS_SIZE) != 0) {
      error("Problem extracting RSA exponent, modulus");
      ssl_rkey_free(server_public_key);
      return False;
    }
    ssl_rkey_free(server_public_key);
    return True;                /* There's some garbage here we don't care about */
  }
  return s_check_end(s);
}

/* Process crypto information blob */
static void sec_process_crypt_info(STREAM s) {
  uint8 *server_random = NULL;
  uint8 modulus[SEC_MAX_MODULUS_SIZE];
  uint8 exponent[SEC_EXPONENT_SIZE];
  uint32 rc4_key_size;

  memset(modulus, 0, sizeof(modulus));
  memset(exponent, 0, sizeof(exponent));
  if (!sec_parse_crypt_info(s, &rc4_key_size, &server_random, modulus, exponent)) {
    DEBUG(("Failed to parse crypt info\n"));
    return;
  }
  DEBUG(("Generating client random\n"));
  generate_random(g_client_random);
  sec_rsa_encrypt(g_sec_crypted_random, g_client_random, SEC_RANDOM_SIZE, g_server_public_key_len, modulus, exponent);
  sec_generate_keys(g_client_random, server_random, rc4_key_size);
}


/* Process SRV_INFO, find RDP version supported by server */
static void sec_process_srv_info(STREAM s) {
  in_uint16_le(s, g_server_rdp_version);
  if (verbose)
    hydra_report(stderr, "[VERBOSE] Server RDP version is %d\n", g_server_rdp_version);
  if (1 == g_server_rdp_version) {
    g_use_rdp5 = 0;
    g_server_depth = 8;
  }
}


/* Process connect response data blob */
void sec_process_mcs_data(STREAM s) {
  uint16 tag, length;
  uint8 *next_tag;
  uint8 len;

  in_uint8s(s, 21);             /* header (T.124 ConferenceCreateResponse) */
  in_uint8(s, len);
  if (len & 0x80)
    in_uint8(s, len);

  while (s->p < s->end) {
    in_uint16_le(s, tag);
    in_uint16_le(s, length);

    if (length <= 4)
      return;

    next_tag = s->p + length - 4;

    switch (tag) {
    case SEC_TAG_SRV_INFO:
      sec_process_srv_info(s);
      break;

    case SEC_TAG_SRV_CRYPT:
      sec_process_crypt_info(s);
      break;

    case SEC_TAG_SRV_CHANNELS:
      break;

    default:
      unimpl("response tag 0x%x\n", tag);
    }

    s->p = next_tag;
  }
}

/* Receive secure transport packet */
STREAM sec_recv(uint8 * rdpver) {
  uint32 sec_flags;
  uint16 channel = 0;
  STREAM s;

  while ((s = mcs_recv(&channel, rdpver)) != NULL) {
    if (rdpver != NULL) {
      if (*rdpver != 3) {
        if (*rdpver & 0x80) {
          in_uint8s(s, 8);      /* signature */
          sec_decrypt(s->p, s->end - s->p);
        }
        return s;
      }
    }
    //if (g_encryption || !g_licence_issued)
    if (g_encryption) {
      in_uint32_le(s, sec_flags);

      if (sec_flags & SEC_ENCRYPT) {
        in_uint8s(s, 8);        /* signature */
        sec_decrypt(s->p, s->end - s->p);
      }

      if (sec_flags & SEC_LICENCE_NEG) {
        //licence_process(s);
        continue;
      }

      if (sec_flags & 0x0400) { /* SEC_REDIRECT_ENCRYPT */
        uint8 swapbyte;

        in_uint8s(s, 8);        /* signature */
        sec_decrypt(s->p, s->end - s->p);

        /* Check for a redirect packet, starts with 00 04 */
        if (s->p[0] == 0 && s->p[1] == 4) {
          /* for some reason the PDU and the length seem to be swapped.
             This isn't good, but we're going to do a byte for byte
             swap.  So the first foure value appear as: 00 04 XX YY,
             where XX YY is the little endian length. We're going to
             use 04 00 as the PDU type, so after our swap this will look
             like: XX YY 04 00 */
          swapbyte = s->p[0];
          s->p[0] = s->p[2];
          s->p[2] = swapbyte;

          swapbyte = s->p[1];
          s->p[1] = s->p[3];
          s->p[3] = swapbyte;

          swapbyte = s->p[2];
          s->p[2] = s->p[3];
          s->p[3] = swapbyte;
        }
#ifdef WITH_DEBUG
        /* warning!  this debug statement will show passwords in the clear! */
        hexdump(s->p, s->end - s->p);
#endif
      }

    }

    if (channel != MCS_GLOBAL_CHANNEL) {
      if (rdpver != NULL)
        *rdpver = 0xff;
      return s;
    }

    return s;
  }

  return NULL;
}

/* Establish a secure connection */
BOOL sec_connect(char *server, char *username, BOOL reconnect) {
  struct stream mcs_data;

  /* We exchange some RDP data during the MCS-Connect */
  mcs_data.size = 512;
  mcs_data.end = mcs_data.p = mcs_data.data = (uint8 *) xmalloc(mcs_data.size);
  sec_out_mcs_data(&mcs_data);

  if (!mcs_connect(server, &mcs_data, username, reconnect))
    return False;
  if (g_encryption)
    sec_establish_key();
  free(mcs_data.data);
  mcs_data.data = NULL;
  return True;
}

/* Disconnect a connection */
void sec_disconnect(void) {
  mcs_disconnect();
}

/* reset the state of the sec layer */
void sec_reset_state(void) {
  g_server_rdp_version = 0;
  g_sec_encrypt_use_count = 0;
  g_sec_decrypt_use_count = 0;
  mcs_reset_state();
}



/* Read field indicating which parameters are present */
static void rdp_in_present(STREAM s, uint32 * present, uint8 flags, int size) {
  uint8 bits;
  int i;

  if (flags & RDP_ORDER_SMALL) {
    size--;
  }

  if (flags & RDP_ORDER_TINY) {
    if (size < 2)
      size = 0;
    else
      size -= 2;
  }

  *present = 0;
  for (i = 0; i < size; i++) {
    in_uint8(s, bits);
    *present |= bits << (i * 8);
  }
}

/* Read a co-ordinate (16-bit, or 8-bit delta) */
static void rdp_in_coord(STREAM s, sint16 * coord, BOOL delta) {
  sint8 change;

  if (delta) {
    in_uint8(s, change);
    *coord += change;
  } else {
    in_uint16_le(s, *coord);
  }
}

/* Read a colour entry */
static void rdp_in_colour(STREAM s, uint32 * colour) {
  uint32 i;

  in_uint8(s, i);
  *colour = i;
  in_uint8(s, i);
  *colour |= i << 8;
  in_uint8(s, i);
  *colour |= i << 16;
}

/* Parse bounds information */
static BOOL rdp_parse_bounds(STREAM s, BOUNDS * bounds) {
  uint8 present;

  in_uint8(s, present);

  if (present & 1)
    rdp_in_coord(s, &bounds->left, False);
  else if (present & 16)
    rdp_in_coord(s, &bounds->left, True);

  if (present & 2)
    rdp_in_coord(s, &bounds->top, False);
  else if (present & 32)
    rdp_in_coord(s, &bounds->top, True);

  if (present & 4)
    rdp_in_coord(s, &bounds->right, False);
  else if (present & 64)
    rdp_in_coord(s, &bounds->right, True);

  if (present & 8)
    rdp_in_coord(s, &bounds->bottom, False);
  else if (present & 128)
    rdp_in_coord(s, &bounds->bottom, True);

  return s_check(s);
}

/* Process an opaque rectangle order */
static void process_rect(STREAM s, RECT_ORDER * os, uint32 present, BOOL delta) {
  uint32 i;

  if (present & 0x01)
    rdp_in_coord(s, &os->x, delta);

  if (present & 0x02)
    rdp_in_coord(s, &os->y, delta);

  if (present & 0x04)
    rdp_in_coord(s, &os->cx, delta);

  if (present & 0x08)
    rdp_in_coord(s, &os->cy, delta);

  if (present & 0x10) {
    in_uint8(s, i);
    os->colour = (os->colour & 0xffffff00) | i;
  }

  if (present & 0x20) {
    in_uint8(s, i);
    os->colour = (os->colour & 0xffff00ff) | (i << 8);
  }

  if (present & 0x40) {
    in_uint8(s, i);
    os->colour = (os->colour & 0xff00ffff) | (i << 16);
  }

  DEBUG(("RECT(x=%d,y=%d,cx=%d,cy=%d,fg=0x%x)\n", os->x, os->y, os->cx, os->cy, os->colour));
}

/* Process a desktop save order */
static void process_desksave(STREAM s, DESKSAVE_ORDER * os, uint32 present, BOOL delta) {
  int width, height;

  if (present & 0x01)
    in_uint32_le(s, os->offset);

  if (present & 0x02)
    rdp_in_coord(s, &os->left, delta);

  if (present & 0x04)
    rdp_in_coord(s, &os->top, delta);

  if (present & 0x08)
    rdp_in_coord(s, &os->right, delta);

  if (present & 0x10)
    rdp_in_coord(s, &os->bottom, delta);

  if (present & 0x20)
    in_uint8(s, os->action);

  DEBUG(("DESKSAVE(l=%d,t=%d,r=%d,b=%d,off=%d,op=%d)\n", os->left, os->top, os->right, os->bottom, os->offset, os->action));

  width = os->right - os->left + 1;
  height = os->bottom - os->top + 1;
}

/* Process a memory blt order */
static void process_memblt(STREAM s, MEMBLT_ORDER * os, uint32 present, BOOL delta) {
  //on win 7, vista, 2008, the login failed has to be catched here
  if (present & 0x0001) {
    in_uint8(s, os->cache_id);
    in_uint8(s, os->colour_table);
  }

  if (present & 0x0002)
    rdp_in_coord(s, &os->x, delta);

  if (present & 0x0004)
    rdp_in_coord(s, &os->y, delta);

  if (present & 0x0008)
    rdp_in_coord(s, &os->cx, delta);

  if (present & 0x0010)
    rdp_in_coord(s, &os->cy, delta);

  if (present & 0x0020)
    in_uint8(s, os->opcode);

  if (present & 0x0040)
    rdp_in_coord(s, &os->srcx, delta);

  if (present & 0x0080)
    rdp_in_coord(s, &os->srcy, delta);

  if (present & 0x0100)
    in_uint16_le(s, os->cache_idx);

  DEBUG(("MEMBLT(op=0x%x,x=%d,y=%d,cx=%d,cy=%d,id=%d,idx=%d)\n", os->opcode, os->x, os->y, os->cx, os->cy, os->cache_id, os->cache_idx));
  //MEMBLT(op=0xcc,x=640,y=128,cx=64,cy=64,id=2,idx=117) => win8 failed

  if ((os->opcode == 0xcc && os->x == 740 && os->y == 448 && os->cx == 60 && os->cy == 56 && os->cache_id == 2) ||
      (os->opcode == 0xcc && os->x == 640 && os->y == 128 && os->cx == 64 && os->cy == 64 && os->cache_id == 2 && os->cache_idx > 100)) {
    if (debug)
      hydra_report(stderr, "[DEBUG] Login failed from process_memblt\n");
    login_result = LOGIN_FAIL;
  }
}

/* Process a text order */
static void process_text2(STREAM s, TEXT2_ORDER * os, uint32 present, BOOL delta) {
  int i;

  if (present & 0x000001)
    in_uint8(s, os->font);

  if (present & 0x000002)
    in_uint8(s, os->flags);

  if (present & 0x000004)
    in_uint8(s, os->opcode);

  if (present & 0x000008)
    in_uint8(s, os->mixmode);

  if (present & 0x000010)
    rdp_in_colour(s, &os->fgcolour);

  if (present & 0x000020)
    rdp_in_colour(s, &os->bgcolour);

  if (present & 0x000040)
    in_uint16_le(s, os->clipleft);

  if (present & 0x000080)
    in_uint16_le(s, os->cliptop);

  if (present & 0x000100)
    in_uint16_le(s, os->clipright);

  if (present & 0x000200)
    in_uint16_le(s, os->clipbottom);

  if (present & 0x000400)
    in_uint16_le(s, os->boxleft);

  if (present & 0x000800)
    in_uint16_le(s, os->boxtop);

  if (present & 0x001000)
    in_uint16_le(s, os->boxright);

  if (present & 0x002000)
    in_uint16_le(s, os->boxbottom);

  //rdp_parse_brush(s, &os->brush, present >> 14);

  if (present & 0x080000)
    in_uint16_le(s, os->x);

  if (present & 0x100000)
    in_uint16_le(s, os->y);

  if (present & 0x200000) {
    in_uint8(s, os->length);
    in_uint8a(s, os->text, os->length);
  }
  //printf("TEXT2(x=%d,y=%d,cl=%d,ct=%d,cr=%d,cb=%d,bl=%d,bt=%d,br=%d,bb=%d,bs=%d,bg=0x%x,fg=0x%x,font=%d,fl=0x%x,op=0x%x,mix=%d,n=%d)\n", os->x, os->y, os->clipleft, os->cliptop, os->clipright, os->clipbottom, os->boxleft, os->boxtop, os->boxright, os->boxbottom, , os->bgcolour, os->fgcolour, os->font, os->flags, os->opcode, os->mixmode, os->length);

  if (debug) {
    printf("[DEBUG] process_text2: ");

    for (i = 0; i < os->length; i++)
      printf("%02x ", os->text[i]);
    printf(" *** ");

    printf("size: %d\n", os->length);
  }
  //there is no way to determine if the message from w2k is a success or failure at first
  //so we identify it here and set the os version as win 2000 same for win2k3
  if (!memcmp(os->text, LOGON_MESSAGE_2K, 31)) {
    os_version = 2000;
  }
  if (!memcmp(os->text, LOGON_MESSAGE_FAILED_2K3, 18)) {
    os_version = 2003;
  }
  //on win2k, error can be fe 00 00 or fe 02 00
  if (((os->text[0] == 254) && (os->text[2] == 0)) || (!memcmp(os->text, LOGON_MESSAGE_FAILED_XP, 18))) {
    if (debug)
      hydra_report(stderr, "[DEBUG] login failed from process_text2\n");
    login_result = LOGIN_FAIL;
  } else {
    //if it's not an well known error and if it's not just traffic from win 2000 server

    if ((os_version == 2000) && (os->length > 50)) {
      if (debug)
        hydra_report(stderr, "[DEBUG] login success from process_text2\n");
      login_result = LOGIN_SUCC;
    }
  }
}

/* Process a secondary order */
static void process_secondary_order(STREAM s) {
  /* The length isn't calculated correctly by the server.
   * For very compact orders the length becomes negative
   * so a signed integer must be used. */
  uint16 length;
  uint16 flags;
  uint8 type;
  uint8 *next_order;

  in_uint16_le(s, length);
  in_uint16_le(s, flags);       /* used by bmpcache2 */
  in_uint8(s, type);

  next_order = s->p + (sint16) length + 7;

  /*
     switch (type)
     {
     case RDP_ORDER_RAW_BMPCACHE:
     break;

     case RDP_ORDER_COLCACHE:
     break;

     case RDP_ORDER_BMPCACHE:
     break;

     case RDP_ORDER_FONTCACHE:
     process_fontcache(s);
     break;

     case RDP_ORDER_RAW_BMPCACHE2:
     break;

     case RDP_ORDER_BMPCACHE2:
     break;

     case RDP_ORDER_BRUSHCACHE:
     process_brushcache(s, flags);
     break;

     default:
     unimpl("secondary order %d\n", type);
     }
   */
  s->p = next_order;
}

/* Process an order PDU */
void process_orders(STREAM s, uint16 num_orders) {
  RDP_ORDER_STATE *os = &g_order_state;
  uint32 present;
  uint8 order_flags;
  int size, processed = 0;
  BOOL delta;

  while (processed < num_orders) {
    in_uint8(s, order_flags);

    if (os_version == 2003)
      os_version = 0;

    if (!(order_flags & RDP_ORDER_STANDARD)) {
      //error("order parsing failed\n");
      //we detected the os is a win 2000 version and the next text msg will be either an error LOGON_MESSAGE_FAILED_2K
      //or any other traffic indicating the logon was successfull, so we reset the os_version and let process_text2 handle the msg
      if (os_version == 2003)
        login_result = LOGIN_SUCC;
      break;
    }

    if (order_flags & RDP_ORDER_SECONDARY) {
      process_secondary_order(s);
    } else {
      if (order_flags & RDP_ORDER_CHANGE) {
        in_uint8(s, os->order_type);
      }

      switch (os->order_type) {
      case RDP_ORDER_TRIBLT:
      case RDP_ORDER_TEXT2:
        size = 3;
        break;

      case RDP_ORDER_PATBLT:
      case RDP_ORDER_MEMBLT:
      case RDP_ORDER_LINE:
      case RDP_ORDER_POLYGON2:
      case RDP_ORDER_ELLIPSE2:
        size = 2;
        break;

      default:
        size = 1;
      }

      rdp_in_present(s, &present, order_flags, size);

      if (order_flags & RDP_ORDER_BOUNDS) {
        if (!(order_flags & RDP_ORDER_LASTBOUNDS))
          rdp_parse_bounds(s, &os->bounds);

      }

      delta = order_flags & RDP_ORDER_DELTA;

//printf("order %d\n", os->order_type);

      if (login_result)
        return;

      switch (os->order_type) {

      case RDP_ORDER_RECT:
        process_rect(s, &os->rect, present, delta);
        break;

      case RDP_ORDER_DESKSAVE:
        process_desksave(s, &os->desksave, present, delta);
        break;

      case RDP_ORDER_MEMBLT:
        process_memblt(s, &os->memblt, present, delta);
        break;

      case RDP_ORDER_TEXT2:
        process_text2(s, &os->text2, present, delta);
        break;

      default:
        if (debug)
          printf("[DEBUG] unknown order_type: %d\n", os->order_type);

      }
    }

    processed++;
  }
}

/* Reset order state */
void reset_order_state(void) {
  memset(&g_order_state, 0, sizeof(g_order_state));
  g_order_state.order_type = RDP_ORDER_PATBLT;
}

/* Disconnect from the RDP layer */
void rdp_disconnect(void) {
  sec_disconnect();
}


void rdp5_process(STREAM s) {
  uint16 length, count;
  uint8 type, ctype;
  uint8 *next;

  struct stream *ts;

  while (s->p < s->end) {
    in_uint8(s, type);
    if (type & RDP5_COMPRESSED) {
      in_uint8(s, ctype);
      in_uint16_le(s, length);
      type ^= RDP5_COMPRESSED;
    } else {
      ctype = 0;
      in_uint16_le(s, length);
    }
    g_next_packet = next = s->p + length;
    ts = s;
//printf("type: %d\n", type);
    switch (type) {
    case 0:                    /* update orders */
      in_uint16_le(ts, count);
      process_orders(ts, count);
      break;

    }

    s->p = next;
  }
}


/* Receive an RDP packet */
static STREAM rdp_recv(uint8 * type) {
  static STREAM rdp_s;
  uint16 length, pdu_type;
  uint8 rdpver;

  if ((rdp_s == NULL) || (g_next_packet >= rdp_s->end) || (g_next_packet == NULL)) {
    rdp_s = sec_recv(&rdpver);
    if (rdp_s == NULL)
      return NULL;
    if (rdpver == 0xff) {
      g_next_packet = rdp_s->end;
      *type = 0;
      return rdp_s;
    } else if (rdpver != 3) {
      /* rdp5_process should move g_next_packet ok */
      rdp5_process(rdp_s);
      *type = 0;
      return rdp_s;
    }

    g_next_packet = rdp_s->p;
  } else {
    rdp_s->p = g_next_packet;
  }

  in_uint16_le(rdp_s, length);
  /* 32k packets are really 8, keepalive fix */
  if (length == 0x8000) {
    g_next_packet += 8;
    *type = 0;
    return rdp_s;
  }
  in_uint16_le(rdp_s, pdu_type);
  in_uint8s(rdp_s, 2);          /* userid */
  *type = pdu_type & 0xf;

  g_next_packet += length;
  return rdp_s;
}

/* used in uiports and rdp_main_loop, processes the rdp packets waiting */
BOOL rdp_loop(BOOL * deactivated, uint32 * ext_disc_reason) {
  uint8 type;
  BOOL cont = True;
  STREAM s;

  while (cont) {
    s = rdp_recv(&type);

    if (s == NULL)
      return False;
    switch (type) {
    case RDP_PDU_DEMAND_ACTIVE:
      process_demand_active(s);
      *deactivated = False;
      break;
    case RDP_PDU_DEACTIVATE:
      DEBUG(("RDP_PDU_DEACTIVATE\n"));
      *deactivated = True;
      break;
    case RDP_PDU_REDIRECT:
      break;
    case RDP_PDU_DATA:
      process_data_pdu(s, ext_disc_reason);
      break;
    case 0:
      break;
    default:
      unimpl("PDU %d\n", type);
    }
    cont = g_next_packet < s->end;
  }
  return True;
}

/* Process incoming packets */
int rdp_main_loop(BOOL * deactivated, uint32 * ext_disc_reason) {
  while (rdp_loop(deactivated, ext_disc_reason)) {
    if (login_result != LOGIN_UNKN) {
      return login_result;
    }
  }
  return 0;
}



/* Parse a logon info packet */
static void rdp_send_logon_info(uint32 flags, char *domain, char *user, char *password, char *program, char *directory) {
  char *ipaddr = tcp_get_address();
  int len_domain = 2 * strlen(domain);
  int len_user = 2 * strlen(user);
  int len_password = 2 * strlen(password);
  int len_program = 2 * strlen(program);
  int len_directory = 2 * strlen(directory);
  int len_ip = 2 * strlen(ipaddr);
  int len_dll = 2 * strlen("C:\\WINNT\\System32\\mstscax.dll");
  int packetlen = 0;
  uint32 sec_flags = g_encryption ? (SEC_LOGON_INFO | SEC_ENCRYPT) : SEC_LOGON_INFO;
  STREAM s = NULL;
  time_t t = time(NULL);
  time_t tzone;
  uint8 security_verifier[16];

  if (!g_use_rdp5 || 1 == g_server_rdp_version) {
    DEBUG_RDP5(("Sending RDP4-style Logon packet\n"));

    s = sec_init(sec_flags, 18 + len_domain + len_user + len_password + len_program + len_directory + 10);

    out_uint32(s, 0);
    out_uint32_le(s, flags);
    out_uint16_le(s, len_domain);
    out_uint16_le(s, len_user);
    out_uint16_le(s, len_password);
    out_uint16_le(s, len_program);
    out_uint16_le(s, len_directory);
    rdp_out_unistr(s, domain, len_domain);
    rdp_out_unistr(s, user, len_user);
    rdp_out_unistr(s, password, len_password);
    rdp_out_unistr(s, program, len_program);
    rdp_out_unistr(s, directory, len_directory);
  } else {

    flags |= RDP_LOGON_BLOB;
    DEBUG_RDP5(("Sending RDP5-style Logon packet\n"));
    packetlen = 4 +             /* Unknown uint32 */
      4 +                       /* flags */
      2 +                       /* len_domain */
      2 +                       /* len_user */
      (flags & RDP_LOGON_AUTO ? 2 : 0) +        /* len_password */
      (flags & RDP_LOGON_BLOB && !(flags & RDP_LOGON_AUTO) ? 2 : 0) +   /* Length of BLOB */
      2 +                       /* len_program */
      2 +                       /* len_directory */
      (0 < len_domain ? len_domain : 2) +       /* domain */
      len_user +                /* len user */
      (flags & RDP_LOGON_AUTO ? len_password : 0) +     /* len pass */
      0 +                       /* We have no 512 byte BLOB. Perhaps we must? */
      (flags & RDP_LOGON_BLOB && !(flags & RDP_LOGON_AUTO) ? 2 : 0) +   /* After the BLOB is a unknown int16. If there is a BLOB, that is. */
      (0 < len_program ? len_program : 2) +     /* program */
      (0 < len_directory ? len_directory : 2) + /* dir */
      2 +                       /* Unknown (2) */
      2 +                       /* Client ip length */
      len_ip +                  /* Client ip */
      2 +                       /* DLL string length */
      len_dll +                 /* DLL string */
      4 +                       /* zone */
      strlen("GTB, normaltid") * 2 +    /* zonestring */
      1 +                       /* len */
      5 * 4 +                   /* some int32 */
      2 * strlen("GTB, sommartid") +    /* zonestring */
      1 +                       /* len */
      5 * 4 +                   /* some int32 */
      2 * 4 +                   /* some int32 */
      (g_has_reconnect_random ? 14 + sizeof(security_verifier) : 2) + 105 +     /* ??? we need this */
      0;                        // end
//printf("pl: %d - flags %d - AUTO %d - BLOB %d\n", packetlen, flags, RDP_LOGON_AUTO, RDP_LOGON_BLOB);

    s = sec_init(sec_flags, packetlen);
    DEBUG_RDP5(("Called sec_init with packetlen %d\n", packetlen));

    out_uint32(s, 0);           /* Unknown */
    out_uint32_le(s, flags);
    out_uint16_le(s, len_domain);
    out_uint16_le(s, len_user);
    if (flags & RDP_LOGON_AUTO) {
      out_uint16_le(s, len_password);
    }
    if (flags & RDP_LOGON_BLOB && !(flags & RDP_LOGON_AUTO)) {
      out_uint16_le(s, 0);
    }
    out_uint16_le(s, len_program);
    out_uint16_le(s, len_directory);
    if (0 < len_domain)
      rdp_out_unistr(s, domain, len_domain);
    else
      out_uint16_le(s, 0);
    rdp_out_unistr(s, user, len_user);
    if (flags & RDP_LOGON_AUTO) {
      rdp_out_unistr(s, password, len_password);
    }
    if (flags & RDP_LOGON_BLOB && !(flags & RDP_LOGON_AUTO)) {
      out_uint16_le(s, 0);
    }
    if (0 < len_program) {
      rdp_out_unistr(s, program, len_program);
    } else {
      out_uint16_le(s, 0);
    }
    if (0 < len_directory) {
      rdp_out_unistr(s, directory, len_directory);
    } else {
      out_uint16_le(s, 0);
    }
    /* TS_EXTENDED_INFO_PACKET */
    out_uint16_le(s, 2);        /* clientAddressFamily = AF_INET */
    out_uint16_le(s, len_ip + 2);       /* cbClientAddress, Length of client ip */
    rdp_out_unistr(s, ipaddr, len_ip);  /* clientAddress */
    out_uint16_le(s, len_dll + 2);      /* cbClientDir */
    rdp_out_unistr(s, "C:\\WINNT\\System32\\mstscax.dll", len_dll);     /* clientDir */

    /* TS_TIME_ZONE_INFORMATION */
    tzone = (mktime(gmtime(&t)) - mktime(localtime(&t))) / 60;
    out_uint32_le(s, tzone);
    rdp_out_unistr(s, "GTB, normaltid", 2 * strlen("GTB, normaltid"));
    out_uint8s(s, 62 - 2 * strlen("GTB, normaltid"));
    out_uint32_le(s, 0x0a0000);
    out_uint32_le(s, 0x050000);
    out_uint32_le(s, 3);
    out_uint32_le(s, 0);
    out_uint32_le(s, 0);
    rdp_out_unistr(s, "GTB, sommartid", 2 * strlen("GTB, sommartid"));
    out_uint8s(s, 62 - 2 * strlen("GTB, sommartid"));
    out_uint32_le(s, 0x30000);
    out_uint32_le(s, 0x050000);
    out_uint32_le(s, 2);
    out_uint32(s, 0);
    out_uint32_le(s, 0xffffffc4);       /* DaylightBias */

    /* Rest of TS_EXTENDED_INFO_PACKET */
    out_uint32_le(s, 0xfffffffe);       /* clientSessionId, consider changing to 0 */
    out_uint32_le(s, g_rdp5_performanceflags);

    /* Client Auto-Reconnect */
    if (g_has_reconnect_random) {
      out_uint16_le(s, 28);     /* cbAutoReconnectLen */
      /* ARC_CS_PRIVATE_PACKET */
      out_uint32_le(s, 28);     /* cbLen */
      out_uint32_le(s, 1);      /* Version */
      out_uint32_le(s, g_reconnect_logonid);    /* LogonId */
      ssl_hmac_md5(g_reconnect_random, sizeof(g_reconnect_random), g_client_random, SEC_RANDOM_SIZE, security_verifier);
      out_uint8a(s, security_verifier, sizeof(security_verifier));
    } else {
      out_uint16_le(s, 0);      /* cbAutoReconnectLen */
    }

  }
  s_mark_end(s);
  sec_send(s, sec_flags);
}

/* Establish a connection up to the RDP layer */
BOOL rdp_connect(char *server, uint32 flags, char *domain, char *login, char *password, char *command, char *directory, BOOL reconnect) {

  if (!sec_connect(server, login, reconnect))
    return False;

  rdp_send_logon_info(flags, domain, login, password, command, directory);
  return True;
}

int start_rdp(int s, char *ip, int port, unsigned char options, char *miscptr, FILE * fp) {
  char *empty = "";
  char *login, *pass;
  char server[64];
  char domain[256];
  char shell[256];
  char directory[256];
  BOOL deactivated = 0;
  uint32 flags, ext_disc_reason = 0;

  flags = RDP_LOGON_NORMAL;
  flags |= RDP_LOGON_AUTO;

  os_version = 0;
  g_redirect = False;
  g_redirect_flags = 0;
  login_result = LOGIN_UNKN;

  shell[0] = directory[0] = 0;
  memset(domain, 0, sizeof(domain));

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  strcpy(server, hydra_address2string(ip));

  if ((miscptr != NULL) && (strlen(miscptr) > 0)) {
    strncpy(domain, miscptr, sizeof(domain) - 1);
    domain[sizeof(domain) - 1] = 0;
  }

  if (!rdp_connect(server, flags, domain, login, pass, shell, directory, g_redirect))
    return 3;

  rdp_main_loop(&deactivated, &ext_disc_reason);

  if (login_result == LOGIN_SUCC) {
    hydra_report_found_host(port, ip, "rdp", fp);
    hydra_completed_pair_found();
  } else {
    hydra_completed_pair();
  }

  rdp_disconnect();

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 2;
  return 1;

}

/* Client program */
void service_rdp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
  int run = 1, next_run = 1;
  int myport = PORT_RDP;

  if (port != 0)
    myport = port;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;

  while (1) {
    next_run = 0;
    switch (run) {
    case 1:                    /* run the cracking function */
      rdesktop_reset_state();
      g_sock = hydra_connect_tcp(ip, myport);
      if (g_sock < 0) {
        hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int) getpid());
        hydra_child_exit(1);
      }
      next_run = start_rdp(g_sock, ip, port, options, miscptr, fp);
      break;
    case 2:                    /* clean exit */
      if (g_sock >= 0)
        rdp_disconnect();
      hydra_child_exit(0);
      return;
    case 3:                    /* connection error case */
      hydra_child_exit(1);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

/* Generate a 32-byte random for the secure transport code. */
void generate_random(uint8 * random) {
  struct stat st;
  struct tms tmsbuf;
  SSL_MD5 md5;
  uint32 *r;
  int fd, n;

  /* If we have a kernel random device, try that first */
  if (((fd = open("/dev/urandom", O_RDONLY)) != -1)
      || ((fd = open("/dev/random", O_RDONLY)) != -1)) {
    n = read(fd, random, 32);
    close(fd);
    if (n == 32)
      return;
  }

  r = (uint32 *) random;
  r[0] = (getpid()) | (getppid() << 16);
  r[1] = (getuid()) | (getgid() << 16);
  r[2] = times(&tmsbuf);        /* system uptime (clocks) */
  gettimeofday((struct timeval *) &r[3], NULL); /* sec and usec */
  stat("/tmp", &st);
  r[5] = st.st_atime;
  r[6] = st.st_mtime;
  r[7] = st.st_ctime;

  /* Hash both halves with MD5 to obscure possible patterns */
  ssl_md5_init(&md5);
  ssl_md5_update(&md5, random, 16);
  ssl_md5_final(&md5, random);
  ssl_md5_update(&md5, random + 16, 16);
  ssl_md5_final(&md5, random + 16);
}

/* malloc; exit if out of memory */
void *xmalloc(int size) {
  void *mem = malloc(size);

  if (mem == NULL) {
    error("xmalloc %d\n", size);
    return NULL;
  }
  return mem;
}

/* strdup */
char *xstrdup(const char *s) {
  char *mem = strdup(s);

  if (mem == NULL) {
    perror("strdup");
    return NULL;
  }
  return mem;
}

/* realloc; exit if out of memory */
void *xrealloc(void *oldmem, size_t size) {
  void *mem;

  if (size == 0)
    size = 1;
//printf("---? %p %d\n", oldmem, size);
  mem = realloc(oldmem, size);
//printf("---!\n");
  if (mem == NULL) {
    error("xrealloc %ld\n", size);
    return NULL;
  }
  return mem;
}

/* report an error */
void error(char *format, ...) {
  va_list ap;

  fprintf(stderr, "[ERROR]: ");

  va_start(ap, format);
  hydra_report(stderr, format, ap);
  va_end(ap);
}

/* report a warning */
void warning(char *format, ...) {
  if (verbose) {
    va_list ap;

    fprintf(stderr, "[VERBOSE]: ");

    va_start(ap, format);
    hydra_report(stderr, format, ap);
    va_end(ap);
  }
}

/* report an unimplemented protocol feature */
void unimpl(char *format, ...) {
  if (debug) {
    va_list ap;

    fprintf(stderr, "[DEBUG] not implemented: ");

    va_start(ap, format);
    hydra_report(stderr, format, ap);
    va_end(ap);
  }
}

/* produce a hex dump */
void hexdump(unsigned char *p, unsigned int len) {
  unsigned char *line = p;
  int i, thisline, offset = 0;

  while (offset < len) {
    printf("%04x ", offset);
    thisline = len - offset;
    if (thisline > 16)
      thisline = 16;

    for (i = 0; i < thisline; i++)
      printf("%02x ", line[i]);

    for (; i < 16; i++)
      printf("   ");

    for (i = 0; i < thisline; i++)
      printf("%c", (line[i] >= 0x20 && line[i] < 0x7f) ? line[i] : '.');

    printf("\n");
    offset += thisline;
    line += thisline;
  }
}

/* Initialise an RDP data packet */
static STREAM rdp_init_data(int maxlen) {
  STREAM s;

  s = sec_init(g_encryption ? SEC_ENCRYPT : 0, maxlen + 18);
  s_push_layer(s, rdp_hdr, 18);

  return s;
}

/* Send an RDP data packet */
static void rdp_send_data(STREAM s, uint8 data_pdu_type) {
  uint16 length;

  s_pop_layer(s, rdp_hdr);
  length = s->end - s->p;

  out_uint16_le(s, length);
  out_uint16_le(s, (RDP_PDU_DATA | 0x10));
  out_uint16_le(s, (g_mcs_userid + 1001));

  out_uint32_le(s, g_rdp_shareid);
  out_uint8(s, 0);              /* pad */
  out_uint8(s, 1);              /* streamid */
  out_uint16_le(s, (length - 14));
  out_uint8(s, data_pdu_type);
  out_uint8(s, 0);              /* compress_type */
  out_uint16(s, 0);             /* compress_len */

  sec_send(s, g_encryption ? SEC_ENCRYPT : 0);
}

/* Input a string in Unicode
 *
 * Returns str_len of string
 */
int rdp_in_unistr(STREAM s, char *string, int str_size, int in_len) {
  int i = 0;
  int len = in_len / 2;
  int rem = 0;

  if (len > str_size - 1) {
    warning("server sent an unexpectedly long string, truncating\n");
    len = str_size - 1;
    rem = in_len - 2 * len;
  }

  while (i < len) {
    in_uint8a(s, &string[i++], 1);
    in_uint8s(s, 1);
  }

  in_uint8s(s, rem);
  string[len] = 0;
  return len;
}

/* Send a control PDU */
static void rdp_send_control(uint16 action) {
  STREAM s;

  s = rdp_init_data(8);

  out_uint16_le(s, action);
  out_uint16(s, 0);             /* userid */
  out_uint32(s, 0);             /* control id */

  s_mark_end(s);
  rdp_send_data(s, RDP_DATA_PDU_CONTROL);
}

/* Send a synchronisation PDU */
static void rdp_send_synchronise(void) {
  STREAM s;

  s = rdp_init_data(4);
  out_uint16_le(s, 1);          /* type */
  out_uint16_le(s, 1002);

  s_mark_end(s);
  rdp_send_data(s, RDP_DATA_PDU_SYNCHRONISE);
}

/* Send a single input event */
void rdp_send_input(uint32 time, uint16 message_type, uint16 device_flags, uint16 param1, uint16 param2) {
  STREAM s;

  switch (message_type) {
  case RDP_INPUT_MOUSE:
    rdp_send_fast_input_mouse(time, device_flags, param1, param2);
    break;
  case RDP_INPUT_SCANCODE:
    rdp_send_fast_input_kbd(time, device_flags, param1);
    break;
  default:
    s = rdp_init_data(16);
    out_uint16_le(s, 1);        /* number of events */
    out_uint16(s, 0);           /* pad */
    out_uint32_le(s, time);
    out_uint16_le(s, message_type);
    out_uint16_le(s, device_flags);
    out_uint16_le(s, param1);
    out_uint16_le(s, param2);
    s_mark_end(s);
    rdp_send_data(s, RDP_DATA_PDU_INPUT);
  }
}

/* Send an (empty) font information PDU */
static void rdp_send_fonts(uint16 seq) {
  STREAM s;

  s = rdp_init_data(8);

  out_uint16(s, 0);             /* number of fonts */
  out_uint16_le(s, 0);          /* pad? */
  out_uint16_le(s, seq);        /* unknown */
  out_uint16_le(s, 0x32);       /* entry size */

  s_mark_end(s);
  rdp_send_data(s, RDP_DATA_PDU_FONT2);
}

/* Output general capability set */
static void rdp_out_general_caps(STREAM s) {
  out_uint16_le(s, RDP_CAPSET_GENERAL);
  out_uint16_le(s, RDP_CAPLEN_GENERAL);
  out_uint16_le(s, 1);          /* OS major type */
  out_uint16_le(s, 3);          /* OS minor type */
  out_uint16_le(s, 0x200);      /* Protocol version */
  out_uint16(s, 0);             /* Pad */
  out_uint16(s, 0);             /* Compression types */
  out_uint16_le(s, g_use_rdp5 ? 0x40d : 0);
  /* Pad, according to T.128. 0x40d seems to 
     trigger
     the server to start sending RDP5 packets. 
     However, the value is 0x1d04 with W2KTSK and
     NT4MS. Hmm.. Anyway, thankyou, Microsoft,
     for sending such information in a padding 
     field.. */
  out_uint16(s, 0);             /* Update capability */
  out_uint16(s, 0);             /* Remote unshare capability */
  out_uint16(s, 0);             /* Compression level */
  out_uint16(s, 0);             /* Pad */
}

/* Output bitmap capability set */
static void rdp_out_bitmap_caps(STREAM s) {
  out_uint16_le(s, RDP_CAPSET_BITMAP);
  out_uint16_le(s, RDP_CAPLEN_BITMAP);
  out_uint16_le(s, g_server_depth);     /* Preferred colour depth */
  out_uint16_le(s, 1);          /* Receive 1 BPP */
  out_uint16_le(s, 1);          /* Receive 4 BPP */
  out_uint16_le(s, 1);          /* Receive 8 BPP */
  out_uint16_le(s, 800);        /* Desktop width */
  out_uint16_le(s, 600);        /* Desktop height */
  out_uint16(s, 0);             /* Pad */
  out_uint16(s, 1);             /* Allow resize */
  out_uint16_le(s, g_bitmap_compression ? 1 : 0);       /* Support compression */
  out_uint16(s, 0);             /* Unknown */
  out_uint16_le(s, 1);          /* Unknown */
  out_uint16(s, 0);             /* Pad */
}

/* Output order capability set */
static void rdp_out_order_caps(STREAM s) {
  uint8 order_caps[32];

  memset(order_caps, 0, 32);
  order_caps[0] = 1;            /* dest blt */
  order_caps[1] = 1;            /* pat blt */
  order_caps[2] = 1;            /* screen blt */
  order_caps[3] = (g_bitmap_cache ? 1 : 0);     /* memblt */
  order_caps[4] = 0;            /* triblt */
  order_caps[8] = 1;            /* line */
  order_caps[9] = 1;            /* line */
  order_caps[10] = 1;           /* rect */
  order_caps[11] = (g_desktop_save ? 1 : 0);    /* desksave */
  order_caps[13] = 1;           /* memblt */
  order_caps[14] = 1;           /* triblt */
  order_caps[20] = 1;           /* polygon */
  order_caps[21] = 1;           /* polygon2 */
  order_caps[22] = 1;           /* polyline */
  order_caps[25] = 1;           /* ellipse */
  order_caps[26] = 1;           /* ellipse2 */
  order_caps[27] = 1;           /* text2 */
  out_uint16_le(s, RDP_CAPSET_ORDER);
  out_uint16_le(s, RDP_CAPLEN_ORDER);

  out_uint8s(s, 20);            /* Terminal desc, pad */
  out_uint16_le(s, 1);          /* Cache X granularity */
  out_uint16_le(s, 20);         /* Cache Y granularity */
  out_uint16(s, 0);             /* Pad */
  out_uint16_le(s, 1);          /* Max order level */
  out_uint16_le(s, 0x147);      /* Number of fonts */
  out_uint16_le(s, 0x2a);       /* Capability flags */
  out_uint8p(s, order_caps, 32);        /* Orders supported */
  out_uint16_le(s, 0x6a1);      /* Text capability flags */
  out_uint8s(s, 6);             /* Pad */
  out_uint32_le(s, g_desktop_save == False ? 0 : 0x38400);      /* Desktop cache size */
  out_uint32(s, 0);             /* Unknown */
  out_uint32_le(s, 0x4e4);      /* Unknown */
}

/* Output bitmap cache capability set */
static void rdp_out_bmpcache_caps(STREAM s) {
  int Bpp;

  out_uint16_le(s, RDP_CAPSET_BMPCACHE);
  out_uint16_le(s, RDP_CAPLEN_BMPCACHE);
  Bpp = (g_server_depth + 7) / 8;       /* bytes per pixel */
  out_uint8s(s, 24);            /* unused */
  out_uint16_le(s, 0x258);      /* entries */
  out_uint16_le(s, 0x100 * Bpp);        /* max cell size */
  out_uint16_le(s, 0x12c);      /* entries */
  out_uint16_le(s, 0x400 * Bpp);        /* max cell size */
  out_uint16_le(s, 0x106);      /* entries */
  out_uint16_le(s, 0x1000 * Bpp);       /* max cell size */
}

/* Output bitmap cache v2 capability set */
static void rdp_out_bmpcache2_caps(STREAM s) {
  out_uint16_le(s, RDP_CAPSET_BMPCACHE2);
  out_uint16_le(s, RDP_CAPLEN_BMPCACHE2);
  out_uint16_le(s, g_bitmap_cache_persist_enable ? 2 : 0);      /* version */
  out_uint16_be(s, 3);          /* number of caches in this set */

  /* max cell size for cache 0 is 16x16, 1 = 32x32, 2 = 64x64, etc */
  out_uint32_le(s, BMPCACHE2_C0_CELLS);
  out_uint32_le(s, BMPCACHE2_C1_CELLS);
  out_uint32_le(s, BMPCACHE2_C2_CELLS);
  out_uint8s(s, 20);            /* other bitmap caches not used */
}

/* Output control capability set */
static void rdp_out_control_caps(STREAM s) {
  out_uint16_le(s, RDP_CAPSET_CONTROL);
  out_uint16_le(s, RDP_CAPLEN_CONTROL);
  out_uint16(s, 0);             /* Control capabilities */
  out_uint16(s, 0);             /* Remote detach */
  out_uint16_le(s, 2);          /* Control interest */
  out_uint16_le(s, 2);          /* Detach interest */
}

/* Output activation capability set */
static void rdp_out_activate_caps(STREAM s) {
  out_uint16_le(s, RDP_CAPSET_ACTIVATE);
  out_uint16_le(s, RDP_CAPLEN_ACTIVATE);
  out_uint16(s, 0);             /* Help key */
  out_uint16(s, 0);             /* Help index key */
  out_uint16(s, 0);             /* Extended help key */
  out_uint16(s, 0);             /* Window activate */
}

/* Output pointer capability set */
static void rdp_out_pointer_caps(STREAM s) {
  out_uint16_le(s, RDP_CAPSET_POINTER);
  out_uint16_le(s, RDP_CAPLEN_POINTER);
  out_uint16(s, 0);             /* Colour pointer */
  out_uint16_le(s, 20);         /* Cache size */
}

/* Output new pointer capability set */
static void rdp_out_newpointer_caps(STREAM s) {
  out_uint16_le(s, RDP_CAPSET_POINTER);
  out_uint16_le(s, RDP_CAPLEN_NEWPOINTER);
  out_uint16_le(s, 1);          /* Colour pointer */
  out_uint16_le(s, 20);         /* Cache size */
  out_uint16_le(s, 20);         /* Cache size for new pointers */
}

/* Output share capability set */
static void rdp_out_share_caps(STREAM s) {
  out_uint16_le(s, RDP_CAPSET_SHARE);
  out_uint16_le(s, RDP_CAPLEN_SHARE);
  out_uint16(s, 0);             /* userid */
  out_uint16(s, 0);             /* pad */
}

/* Output colour cache capability set */
static void rdp_out_colcache_caps(STREAM s) {
  out_uint16_le(s, RDP_CAPSET_COLCACHE);
  out_uint16_le(s, RDP_CAPLEN_COLCACHE);
  out_uint16_le(s, 6);          /* cache size */
  out_uint16(s, 0);             /* pad */
}

/* Output brush cache capability set */
static void rdp_out_brushcache_caps(STREAM s) {
  out_uint16_le(s, RDP_CAPSET_BRUSHCACHE);
  out_uint16_le(s, RDP_CAPLEN_BRUSHCACHE);
  out_uint32_le(s, 1);          /* cache type */
}

static uint8 caps_0x0d[] = {
  0x01, 0x00, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00,
  0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static uint8 caps_0x0c[] = { 0x01, 0x00, 0x00, 0x00 };

static uint8 caps_0x0e[] = { 0x01, 0x00, 0x00, 0x00 };

static uint8 caps_0x10[] = {
  0xFE, 0x00, 0x04, 0x00, 0xFE, 0x00, 0x04, 0x00,
  0xFE, 0x00, 0x08, 0x00, 0xFE, 0x00, 0x08, 0x00,
  0xFE, 0x00, 0x10, 0x00, 0xFE, 0x00, 0x20, 0x00,
  0xFE, 0x00, 0x40, 0x00, 0xFE, 0x00, 0x80, 0x00,
  0xFE, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x08,
  0x00, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00
};

/* Output unknown capability sets */
static void rdp_out_unknown_caps(STREAM s, uint16 id, uint16 length, uint8 * caps) {
  out_uint16_le(s, id);
  out_uint16_le(s, length);
  out_uint8p(s, caps, length - 4);
}

#define RDP5_FLAG 0x0030

/* Send a confirm active PDU */
static void rdp_send_confirm_active(void) {
  STREAM s;
  uint32 sec_flags = g_encryption ? (RDP5_FLAG | SEC_ENCRYPT) : RDP5_FLAG;
  uint16 caplen =
    RDP_CAPLEN_GENERAL + RDP_CAPLEN_BITMAP + RDP_CAPLEN_ORDER +
    RDP_CAPLEN_COLCACHE + RDP_CAPLEN_ACTIVATE + RDP_CAPLEN_CONTROL + RDP_CAPLEN_SHARE + RDP_CAPLEN_BRUSHCACHE + 0x58 + 0x08 + 0x08 + 0x34 /* unknown caps */  +
    4 /* w2k fix, sessionid */ ;

  if (g_use_rdp5) {
    caplen += RDP_CAPLEN_BMPCACHE2;
    caplen += RDP_CAPLEN_NEWPOINTER;
  } else {
    caplen += RDP_CAPLEN_BMPCACHE;
    caplen += RDP_CAPLEN_POINTER;
  }

  s = sec_init(sec_flags, 6 + 14 + caplen + sizeof(RDP_SOURCE));

  out_uint16_le(s, 2 + 14 + caplen + sizeof(RDP_SOURCE));
  out_uint16_le(s, (RDP_PDU_CONFIRM_ACTIVE | 0x10));    /* Version 1 */
  out_uint16_le(s, (g_mcs_userid + 1001));

  out_uint32_le(s, g_rdp_shareid);
  out_uint16_le(s, 0x3ea);      /* userid */
  out_uint16_le(s, sizeof(RDP_SOURCE));
  out_uint16_le(s, caplen);

  out_uint8p(s, RDP_SOURCE, sizeof(RDP_SOURCE));
  out_uint16_le(s, 0xe);        /* num_caps */
  out_uint8s(s, 2);             /* pad */

  rdp_out_general_caps(s);
  rdp_out_bitmap_caps(s);
  rdp_out_order_caps(s);
  if (g_use_rdp5) {
    rdp_out_bmpcache2_caps(s);
    rdp_out_newpointer_caps(s);
  } else {
    rdp_out_bmpcache_caps(s);
    rdp_out_pointer_caps(s);
  }

  rdp_out_colcache_caps(s);
  rdp_out_activate_caps(s);
  rdp_out_control_caps(s);
  rdp_out_share_caps(s);
  rdp_out_brushcache_caps(s);

  rdp_out_unknown_caps(s, 0x0d, 0x58, caps_0x0d);       /* CAPSTYPE_INPUT */
  rdp_out_unknown_caps(s, 0x0c, 0x08, caps_0x0c);       /* CAPSTYPE_SOUND */
  rdp_out_unknown_caps(s, 0x0e, 0x08, caps_0x0e);       /* CAPSTYPE_FONT */
  rdp_out_unknown_caps(s, 0x10, 0x34, caps_0x10);       /* CAPSTYPE_GLYPHCACHE */

  s_mark_end(s);
  sec_send(s, sec_flags);
}

/* Process a general capability set */
static void rdp_process_general_caps(STREAM s) {
  uint16 pad2octetsB;           /* rdp5 flags? */

  in_uint8s(s, 10);
  in_uint16_le(s, pad2octetsB);
  if (!pad2octetsB)
    g_use_rdp5 = False;
}

/* Process a bitmap capability set */
static void rdp_process_bitmap_caps(STREAM s) {
  uint16 width, height, depth;

  in_uint16_le(s, depth);
  in_uint8s(s, 6);
  in_uint16_le(s, width);
  in_uint16_le(s, height);
  DEBUG(("setting desktop size and depth to: %dx%dx%d\n", width, height, depth));
}

/* Process server capabilities */
static void rdp_process_server_caps(STREAM s, uint16 length) {
  int n;
  uint8 *next, *start;
  uint16 ncapsets, capset_type, capset_length;

  start = s->p;

  in_uint16_le(s, ncapsets);
  in_uint8s(s, 2);              /* pad */

  for (n = 0; n < ncapsets; n++) {
    if (s->p > start + length)
      return;

    in_uint16_le(s, capset_type);
    in_uint16_le(s, capset_length);

    next = s->p + capset_length - 4;

    switch (capset_type) {
    case RDP_CAPSET_GENERAL:
      rdp_process_general_caps(s);
      break;

    case RDP_CAPSET_BITMAP:
      rdp_process_bitmap_caps(s);
      break;
    }

    s->p = next;
  }
}

/* Respond to a demand active PDU */
static void process_demand_active(STREAM s) {
  uint8 type;
  uint16 len_src_descriptor, len_combined_caps;

  in_uint32_le(s, g_rdp_shareid);
  in_uint16_le(s, len_src_descriptor);
  in_uint16_le(s, len_combined_caps);
  in_uint8s(s, len_src_descriptor);

  DEBUG(("DEMAND_ACTIVE(id=0x%x)\n", g_rdp_shareid));
  rdp_process_server_caps(s, len_combined_caps);

  rdp_send_confirm_active();
  rdp_send_synchronise();
  rdp_send_control(RDP_CTL_COOPERATE);
  rdp_send_control(RDP_CTL_REQUEST_CONTROL);
  rdp_recv(&type);              /* RDP_PDU_SYNCHRONIZE */
  rdp_recv(&type);              /* RDP_CTL_COOPERATE */
  rdp_recv(&type);              /* RDP_CTL_GRANT_CONTROL */
  rdp_send_input(0, 0, 0, 0, 0);        /* RDP_INPUT_SYNCHRONIZE */
  // here? XXX TODO BUGFIX

  if (g_use_rdp5) {
    rdp_send_fonts(3);
  } else {
    rdp_send_fonts(1);
    rdp_send_fonts(2);
  }

  rdp_recv(&type);              /* RDP_PDU_UNKNOWN 0x28 (Fonts?) */
  reset_order_state();
}

/* Process an update PDU */
static void process_update_pdu(STREAM s) {
  uint16 update_type, count;

  in_uint16_le(s, update_type);

  //ui_begin_update();
  switch (update_type) {
  case RDP_UPDATE_ORDERS:
    in_uint8s(s, 2);            /* pad */
    in_uint16_le(s, count);
    in_uint8s(s, 2);            /* pad */
    process_orders(s, count);
    break;

  case RDP_UPDATE_BITMAP:
    //process_bitmap_updates(s);
    break;

  case RDP_UPDATE_PALETTE:
    //process_palette(s);
    break;

  case RDP_UPDATE_SYNCHRONIZE:
    break;

  default:
    unimpl("update %d\n", update_type);
  }
}


/* Process a disconnect PDU */
void process_disconnect_pdu(STREAM s, uint32 * ext_disc_reason) {
  in_uint32_le(s, *ext_disc_reason);

  DEBUG(("Received disconnect PDU\n"));
}

/* Process data PDU */
static BOOL process_data_pdu(STREAM s, uint32 * ext_disc_reason) {
  uint8 data_pdu_type;
  uint8 ctype;
  uint16 clen;
  uint32 len;

  in_uint8s(s, 6);              /* shareid, pad, streamid */
  in_uint16_le(s, len);
  in_uint8(s, data_pdu_type);
  in_uint8(s, ctype);
  in_uint16_le(s, clen);
  clen -= 18;

  switch (data_pdu_type) {
  case RDP_DATA_PDU_UPDATE:
    process_update_pdu(s);
    break;

  case RDP_DATA_PDU_CONTROL:
    DEBUG(("Received Control PDU\n"));
    break;

  case RDP_DATA_PDU_SYNCHRONISE:
    DEBUG(("Received Sync PDU\n"));
    break;

  case RDP_DATA_PDU_POINTER:
    //process_pointer_pdu(s);
    break;

  case RDP_DATA_PDU_BELL:
    //ui_bell();
    break;

  case RDP_DATA_PDU_LOGON:
    DEBUG(("Received Logon PDU\n"));
    /* User logged on */
    login_result = LOGIN_SUCC;
    return 1;
    break;

  case RDP_DATA_PDU_DISCONNECT:
    process_disconnect_pdu(s, ext_disc_reason);

    /* We used to return true and disconnect immediately here, but
     * Windows Vista sends a disconnect PDU with reason 0 when
     * reconnecting to a disconnected session, and MSTSC doesn't
     * drop the connection.  I think we should just save the status.
     */
    break;

  default:
    unimpl("data PDU %d\n", data_pdu_type);
  }
  return False;
}
#endif

int service_rdp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port) {
  // called before the childrens are forked off, so this is the function
  // which should be filled if initial connections and service setup has to be
  // performed once only.
  //
  // fill if needed.
  // 
  // return codes:
  //   0 all OK
  //   -1  error, hydra will exit, so print a good error message here

  return 0;
}
