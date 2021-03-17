#include "hydra-mod.h"

extern char *HYDRA_EXIT;
extern int32_t child_head_no;
int32_t seq = 1;

const unsigned char icq5_table[] = {0x59, 0x60, 0x37, 0x6B, 0x65, 0x62, 0x46, 0x48, 0x53, 0x61, 0x4C, 0x59, 0x60, 0x57, 0x5B, 0x3D, 0x5E, 0x34, 0x6D, 0x36, 0x50, 0x3F, 0x6F, 0x67, 0x53, 0x61, 0x4C, 0x59, 0x40, 0x47, 0x63, 0x39, 0x50, 0x5F, 0x5F, 0x3F, 0x6F, 0x47, 0x43, 0x69, 0x48, 0x33, 0x31, 0x64, 0x35, 0x5A, 0x4A, 0x42, 0x56, 0x40, 0x67, 0x53, 0x41, 0x07, 0x6C, 0x49, 0x58, 0x3B, 0x4D, 0x46, 0x68, 0x43, 0x69, 0x48,
                                    0x33, 0x31, 0x44, 0x65, 0x62, 0x46, 0x48, 0x53, 0x41, 0x07, 0x6C, 0x69, 0x48, 0x33, 0x51, 0x54, 0x5D, 0x4E, 0x6C, 0x49, 0x38, 0x4B, 0x55, 0x4A, 0x62, 0x46, 0x48, 0x33, 0x51, 0x34, 0x6D, 0x36, 0x50, 0x5F, 0x5F, 0x5F, 0x3F, 0x6F, 0x47, 0x63, 0x59, 0x40, 0x67, 0x33, 0x31, 0x64, 0x35, 0x5A, 0x6A, 0x52, 0x6E, 0x3C, 0x51, 0x34, 0x6D, 0x36, 0x50, 0x5F, 0x5F, 0x3F, 0x4F, 0x37, 0x4B, 0x35,
                                    0x5A, 0x4A, 0x62, 0x66, 0x58, 0x3B, 0x4D, 0x66, 0x58, 0x5B, 0x5D, 0x4E, 0x6C, 0x49, 0x58, 0x3B, 0x4D, 0x66, 0x58, 0x3B, 0x4D, 0x46, 0x48, 0x53, 0x61, 0x4C, 0x59, 0x40, 0x67, 0x33, 0x31, 0x64, 0x55, 0x6A, 0x32, 0x3E, 0x44, 0x45, 0x52, 0x6E, 0x3C, 0x31, 0x64, 0x55, 0x6A, 0x52, 0x4E, 0x6C, 0x69, 0x48, 0x53, 0x61, 0x4C, 0x39, 0x30, 0x6F, 0x47, 0x63, 0x59, 0x60, 0x57, 0x5B, 0x3D, 0x3E,
                                    0x64, 0x35, 0x3A, 0x3A, 0x5A, 0x6A, 0x52, 0x4E, 0x6C, 0x69, 0x48, 0x53, 0x61, 0x6C, 0x49, 0x58, 0x3B, 0x4D, 0x46, 0x68, 0x63, 0x39, 0x50, 0x5F, 0x5F, 0x3F, 0x6F, 0x67, 0x53, 0x41, 0x25, 0x41, 0x3C, 0x51, 0x54, 0x3D, 0x5E, 0x54, 0x5D, 0x4E, 0x4C, 0x39, 0x50, 0x5F, 0x5F, 0x5F, 0x3F, 0x6F, 0x47, 0x43, 0x69, 0x48, 0x33, 0x51, 0x54, 0x5D, 0x6E, 0x3C, 0x31, 0x64, 0x35, 0x5A, 0x00, 0x00};

void fix_packet(char *buf, int32_t len) {
  unsigned long c1, c2;
  unsigned long r1, r2;
  int32_t pos, key, k;

  c1 = buf[8];
  c1 <<= 8;
  c1 |= buf[4];
  c1 <<= 8;
  c1 |= buf[2];
  c1 <<= 8;
  c1 |= buf[6];

  r1 = (rand() % (len - 0x18)) + 0x18;
  r2 = rand() & 0xff;

  c2 = r1;
  c2 <<= 8;
  c2 |= buf[r1];
  c2 <<= 8;
  c2 |= r2;
  c2 <<= 8;
  c2 |= icq5_table[r2];
  c2 ^= 0xff00ff;

  c1 ^= c2;
  buf[0x14] = c1 & 0xff;
  buf[0x15] = (c1 >> 8) & 0xff;
  buf[0x16] = (c1 >> 16) & 0xff;
  buf[0x17] = (c1 >> 24) & 0xff;

  key = len * 0x68656c6cL;
  key += c1;
  pos = 0xa;

  for (; pos < len; pos += 4)
    k = key + icq5_table[pos & 0xff];
}

void icq_header(char *buf, unsigned short cmd, unsigned long uin) {
  buf[0] = 0x02;
  buf[1] = 0x00;
  buf[2] = cmd & 0xff;
  buf[3] = (cmd >> 8) & 0xff;
  buf[4] = seq & 0xff;
  buf[5] = (seq++ >> 8) & 0xff;
  buf[6] = uin & 0xff;
  buf[7] = (uin >> 8) & 0xff;
  buf[8] = (uin >> 16) & 0xff;
  buf[9] = (uin >> 24) & 0xff;
}

int32_t icq_login(int32_t s, char *login, char *pass) {
  unsigned long uin = strtoul(login, NULL, 10);
  char buf[256];
  int32_t len;

  bzero(buf, sizeof(buf));

  icq_header(buf, 0x03e8, uin);
  len = strlen(pass) + 1;
  buf[14] = len;
  memcpy(&buf[16], pass, len);
  buf[16 + len] = 0x78;
  buf[24 + len] = 0x04;
  buf[29 + len] = 0x02;
  buf[39 + len] = 0x08;
  buf[41 + len] = 0x78;

  return (hydra_send(s, buf, 43 + len, 0));
}

int32_t icq_login_1(int32_t s, char *login) {
  unsigned long uin = strtoul(login, NULL, 10);
  char buf[64];

  icq_header(buf, 0x044c, uin);
  return (hydra_send(s, buf, 10, 0));
}

int32_t icq_disconnect(int32_t s, char *login) {
  unsigned long uin = strtoul(login, NULL, 10);
  char buf[64];

  bzero(buf, sizeof(buf));
  icq_header(buf, 0x0438, uin);
  buf[10] = 20;
  memcpy(&buf[12], "B_USER_DISCONNECTED", 20);
  buf[32] = 0x5;
  return (hydra_send(s, buf, 34, 0));
}

int32_t icq_ack(int32_t s, char *login) {
  unsigned long uin = strtoul(login, NULL, 10);
  char buf[64];

  buf[0] = 0x02;
  buf[1] = 0x00;
  buf[2] = 0x0a;
  buf[3] = 0x0;
  buf[4] = seq & 0xff;
  buf[5] = (seq >> 8) & 0xff;
  buf[6] = uin & 0xff;
  buf[7] = (uin >> 8) & 0xff;
  buf[8] = (uin >> 16) & 0xff;
  buf[9] = (uin >> 24) & 0xff;

  return (hydra_send(s, buf, 10, 0));
}

int32_t start_icq(int32_t sock, char *ip, int32_t port, FILE *output, char *miscptr, FILE *fp) {
  unsigned char buf[1024];
  char *login, *pass;
  char *empty = "";
  int32_t i, r;

  if (strlen(login = hydra_get_next_login()) == 0)
    return 2;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  for (i = 0; login[i]; i++)
    if (!isdigit((int32_t)login[i])) {
      fprintf(stderr, "[ERROR] Invalid UIN %s\n, ignoring.", login);
      hydra_completed_pair();
      return 2;
    }

  icq_login(sock, login, pass);

  while (1) {
    if ((r = hydra_recv(sock, (char *)buf, sizeof(buf))) == 0) {
      return 1;
    }

    if (r < 0) {
      if (verbose)
        fprintf(stderr, "[ERROR] Process %d: Can not connect [unreachable]\n", (int32_t)getpid());
      return 3;
    }

    if (buf[2] == 0x5a && buf[3] == 0x00) {
      hydra_report_found_host(port, ip, "icq", output);
      hydra_completed_pair_found();
      icq_ack(sock, login);
      icq_login_1(sock, login);
      hydra_recv(sock, (char *)buf, sizeof(buf));
      icq_ack(sock, login);
      hydra_recv(sock, (char *)buf, sizeof(buf));
      icq_ack(sock, login);
      icq_disconnect(sock, login);
      break;
    } else if ((buf[2] != 10 && buf[2] != 250) || buf[3] != 0) {
      hydra_completed_pair();
      break;
    }

    /*       if((buf[2] != 10 || buf[3] != 0) && (buf[2] != 250 || buf[3] != 0))
     */
  }

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;
  return 1;
}

void service_icq(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_ICQ;

  if (port)
    myport = port;

  port = myport;

  if ((options & OPTION_SSL) != 0 && child_head_no == 0) {
    fprintf(stderr, "[ERROR] You can not use SSL with ICQ!\n");
    hydra_child_exit(0);
  }

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;

  while (1) {
    switch (run) {
    case 1:
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      sock = hydra_connect_udp(ip, myport);
      if (sock < 0) {
        if (quiet != 1)
          fprintf(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      next_run = 2;
      break;
    case 2:
      next_run = start_icq(sock, ip, port, fp, miscptr, fp);
      break;
    case 3:
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(2);
      break;
    default:
      fprintf(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(2);
      break;
    }
    run = next_run;
  }
}

int32_t service_icq_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
