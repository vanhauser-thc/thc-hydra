#include "hydra-mod.h"

/* pcnfs stuff copied from prout.c */

extern char *HYDRA_EXIT;
char *buf;

#define LEN_HDR_RPC 24
#define LEN_AUTH_UNIX 72 + 12

/* RPC common hdr */
struct rpc_hdr { /* 24 */
  unsigned long xid;
  unsigned long type_msg;
  unsigned long version_rpc;
  unsigned long prog_id;
  unsigned long prog_ver;
  unsigned long prog_proc;
};

struct pr_auth_args {
  unsigned long len_clnt;
  char name[64];
  unsigned long len_id;
  char id[32];
  unsigned long len_passwd;
  char passwd[64];
  unsigned long len_comments;
  char comments[255];
};

#define LEN_HDR_PCN_AUTH sizeof(struct pr_auth_args)

/* Lets start ... */

int32_t start_pcnfs(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass, buffer[LEN_HDR_RPC + LEN_AUTH_UNIX + LEN_HDR_PCN_AUTH];
  char *ptr, *pkt = buffer;

  unsigned long *authp;
  struct timeval tv;

  struct rpc_hdr *rpch;
  struct pr_auth_args *prh;

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  memset(pkt, 0, sizeof(buffer));

  rpch = (struct rpc_hdr *)(pkt);
  authp = (unsigned long *)(pkt + LEN_HDR_RPC);
  prh = (struct pr_auth_args *)(pkt + LEN_HDR_RPC + LEN_AUTH_UNIX);

  rpch->xid = htonl(0x32544843);
  rpch->type_msg = htonl(0);
  rpch->version_rpc = htonl(2);
  rpch->prog_id = htonl(150001);
  rpch->prog_ver = htonl(2);
  rpch->prog_proc = htonl(13); /* PCNFSD_PROC_PRAUTH */
  prh->len_clnt = htonl(63);
  prh->len_id = htonl(31);
  prh->len_passwd = htonl(63);
  prh->len_comments = htonl(254);

  strcpy(prh->comments, " Hydra - THC password cracker - visit "
                        "https://github.com/vanhauser-thc/thc-hydra - use only "
                        "allowed for legal purposes ");
  strcpy(prh->name, "localhost");

  ptr = prh->id;
  while (*login) {
    *ptr++ = (*login ^ 0x5b) & 0x7f;
    login++;
  }
  *ptr = 0;
  ptr = prh->passwd;
  while (*pass) {
    *ptr++ = (*pass ^ 0x5b) & 0x7f;
    pass++;
  }
  *ptr = 0;

  gettimeofday(&tv, (struct timezone *)NULL);
  *(authp) = htonl(1);                    /* auth unix */
  *(++authp) = htonl(LEN_AUTH_UNIX - 16); /* length auth */
  *(++authp) = htonl(tv.tv_sec);          /* local time */
  *(++authp) = htonl(9);                  /* length host */
  strcpy((char *)++authp, "localhost");   /* hostname */
  authp += (3);                           /* len(host)%4 */
  *(authp) = htonl(0);                    /* uid root */
  *(++authp) = htonl(0);                  /* gid root */
  *(++authp) = htonl(9);                  /* 9 gid grps */
  /* group root, bin, daemon, sys, adm, disk, wheel, floppy, "user gid" */
  *(++authp) = htonl(0);
  *(++authp) = htonl(1);
  *(++authp) = htonl(2);
  *(++authp) = htonl(3);
  *(++authp) = htonl(4);
  *(++authp) = htonl(6);
  *(++authp) = htonl(10);
  *(++authp) = htonl(11);
  *(++authp) = htonl(0);

  if (hydra_send(s, buffer, sizeof(buffer), 0) < 0) {
    fprintf(stderr, "[ERROR] Could not send data to remote server, reconnecting ...\n");
    return 1;
  }

  if ((buf = hydra_receive_line(s)) == NULL) {
    fprintf(stderr, "[ERROR] Timeout from remote server, reconnecting ...\n");
    return 1;
  }

  /* analyze the output */
  if (buf[2] != 'g' || buf[5] != 32) {
    fprintf(stderr, "[ERROR] RPC answer status : bad proc/version/auth\n");
    free(buf);
    return 3;
  }

  if (buf[27] == 32 && buf[28] == 32 && buf[29] == 32) {
    hydra_report_found_host(port, ip, "pcnfs", fp);
    hydra_completed_pair_found();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
  } else {
    hydra_completed_pair();
    free(buf);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
  }

  return 1;
}

void service_pcnfs(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;

  hydra_register_socket(sp);
  if (port == 0) {
    fprintf(stderr, "[ERROR] pcnfs module called without -s port!\n");
    hydra_child_exit(0);
  }
  if ((options & OPTION_SSL) != 0) {
    fprintf(stderr, "[ERROR] pcnfs module can not be used with SSL!\n");
    hydra_child_exit(0);
  }

  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;

  while (1) {
    next_run = 0;
    switch (run) {
    case 1: /* connect and service init function */
    {
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      //        usleepn(275);
      if ((sock = hydra_connect_udp(ip, port)) < 0) {
        if (quiet != 1)
          fprintf(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      next_run = 2;
      break;
    }
    case 2: /* run the cracking function */
      next_run = start_pcnfs(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(0);
      return;
    default:
      fprintf(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(0);
    }
    run = next_run;
  }
}

int32_t service_pcnfs_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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
