#include "hydra-mod.h"

extern int32_t hydra_data_ready_timed(int32_t socket, long sec, long usec);

extern char *HYDRA_EXIT;
char *buf;

int32_t start_cvs(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *empty = "";
  char *login, *pass, buffer[1024], pass2[513];
  int32_t i;
  char *directory = miscptr;

  /* evil cvs encryption sheme...
          0 111           P 125           p  58
  ! 120   1  52   A  57   Q  55   a 121   q 113
  "  53   2  75   B  83   R  54   b 117   r  32
          3 119   C  43   S  66   c 104   s  90
          4  49   D  46   T 124   d 101   t  44
  % 109   5  34   E 102   U 126   e 100   u  98
  &  72   6  82   F  40   V  59   f  69   v  60
  ' 108   7  81   G  89   W  47   g  73   w  51
  (  70   8  95   H  38   X  92   h  99   x  33
  )  64   9  65   I 103   Y  71   i  63   y  97
  *  76   : 112   J  45   Z 115   j  94   z  62
  +  67   ;  86   K  50           k  93
  , 116   < 118   L  42           l  39
  -  74   = 110   M 123           m  37
  .  68   > 122   N  91           n  61
  /  87   ? 105   O  35   _  56   o  48
  */

  char key[] = {0, 120, 53, 0, 0, 109, 72, 108, 70, 64, 76, 67, 116, 74, 68, 87, 111, 52, 75, 119, 49, 34, 82, 81, 95, 65, 112, 86, 118, 110, 122, 105, 0, 57, 83, 43, 46, 102, 40, 89, 38, 103, 45, 50, 42, 123, 91, 35, 125, 55, 54, 66, 124, 126, 59, 47, 92, 71, 115, 0, 0, 0, 0, 56, 0, 121, 117, 104, 101, 100, 69, 73, 99, 63, 94, 93, 39, 37, 61, 48, 58, 113, 32, 90, 44, 98, 60, 51, 33, 97, 62};

  if (strlen(login = hydra_get_next_login()) == 0)
    login = empty;
  if (strlen(pass = hydra_get_next_password()) == 0)
    pass = empty;

  memset(pass2, 0, sizeof(pass2));
  strncpy(pass2, pass, 512);

  for (i = 0; i < strlen(pass); i++) {
    pass2[i] = key[pass2[i] - 0x20];
  }

  snprintf(buffer, sizeof(buffer), "BEGIN VERIFICATION REQUEST\n%s\n%s\nA%s\nEND VERIFICATION REQUEST\n", directory, login, pass2);

  i = 57 + strlen(directory) + strlen(login) + strlen(pass2);

  if (hydra_send(s, buffer, i - 1, 0) < 0) {
    return 1;
  }

  if (hydra_data_ready_timed(s, 5, 0) > 0) {
    buf = hydra_receive_line(s);
    if (strstr(buf, "I LOVE YOU\n")) {
      hydra_report_found_host(port, ip, "cvs", fp);
      hydra_completed_pair_found();
      free(buf);
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0) {
        return 3;
      }
    } else if (strstr(buf, "no such user") || strstr(buf, "E PAM start error: Critical error - immediate abort\n")) {
      if (verbose) {
        hydra_report(stderr, "[INFO] User %s does not exist, skipping\n", login);
      }
      hydra_completed_pair_skip();
      free(buf);
      if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0) {
        return 3;
      }
    }
    /* "I HATE YOU\n" case */
    free(buf);
    return 3;
  }

  return 3;
}

void service_cvs(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_CVS, mysslport = PORT_CVS_SSL;

  hydra_register_socket(sp);

  if ((miscptr == NULL) || (strlen(miscptr) == 0)) {
    miscptr = "/root";
  }

  while (1) {
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return;

    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0)
        sock = hydra_disconnect(sock);

      //      usleepn(300);
      if ((options & OPTION_SSL) == 0) {
        if (port != 0)
          myport = port;
        sock = hydra_connect_tcp(ip, myport);
        port = myport;
      } else {
        if (port != 0)
          mysslport = port;
        sock = hydra_connect_ssl(ip, mysslport, hostname);
        port = mysslport;
      }

      if (sock < 0) {
        hydra_report(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      next_run = start_cvs(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0)
        sock = hydra_disconnect(sock);
      hydra_child_exit(2);
      return;
    default:
      hydra_report(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

int32_t service_cvs_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_cvs(const char *service) {
  printf("Module cvs is optionally taking the repository name to attack, "
         "default is \"/root\"\n\n");
}
