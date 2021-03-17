
/* mysql 3.2x.x to 4.x support - by mcbethh (at) u-n-f (dot) com */

/* david (dot) maciejak (at) gmail (dot) com for using libmysqlclient-dev,
 * adding support for mysql version 5.x */

#include "hydra-mod.h"

#ifndef HAVE_MATH_H
#include <stdio.h>
void dummy_mysql() { printf("\n"); }

void service_mysql(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) { printf("\n"); }
#else

#include <math.h>

#define DEFAULT_DB "mysql"

#ifndef LIBMYSQLCLIENT
#else
#if defined(HAVE_MYSQL_MYSQL_H)
#include <mysql/mysql.h>
#elif defined(HAVE_MYSQL_H)
#include <mysql.h>
#else
#error libmysqlclient found, but no usable headers available
#endif
MYSQL *mysql = NULL;
#endif

void hydra_hash_password(unsigned long *result, const char *password);
char *hydra_scramble(char *to, const char *message, const char *password);

extern int32_t internal__hydra_recv(int32_t socket, char *buf, int32_t length);
extern int32_t hydra_data_ready_timed(int32_t socket, long sec, long usec);

extern char *HYDRA_EXIT;
char mysqlsalt[9];

/* modified hydra_receive_line, I've striped code which changed every 0x00 to
 * 0x20 */
char *hydra_mysql_receive_line(int32_t socket) {
  char buf[300], *buff, *buff2;
  int32_t i = 0, j = 0, buff_size = 300;

  buff = malloc(buff_size);
  if (buff == NULL)
    return NULL;
  memset(buff, 0, sizeof(buf));

  i = hydra_data_ready_timed(socket, (long)waittime, 0);
  if (i > 0) {
    if ((i = internal__hydra_recv(socket, buff, sizeof(buf))) < 0) {
      free(buff);
      return NULL;
    }
  }
  if (i <= 0) {
    if (debug)
      hydra_report_debug(stderr, "DEBUG_RECV_BEGIN||END\n");
    free(buff);
    return NULL;
  }

  j = 1;
  while (hydra_data_ready(socket) > 0 && j > 0) {
    j = internal__hydra_recv(socket, buf, sizeof(buf));
    if (j > 0) {
      if (i + j > buff_size || (buff2 = realloc(buff, i + j)) == NULL) {
        free(buff);
        return NULL;
      } else {
        buff = buff2;
        buff_size = i + j;
      }
      memcpy(buff + i, &buf, j);
      i += j;
    }
  }

  if (debug)
    hydra_report_debug(stderr, "DEBUG_RECV_BEGIN|%s|END\n", buff);
  return buff;
}

/* check if valid mysql protocol, mysql version and read salt */
char hydra_mysql_init(int32_t sock) {
  char *server_version, *pos, *buf;
  unsigned char protocol;

  buf = hydra_mysql_receive_line(sock);
  if (buf == NULL)
    return 1;

  protocol = buf[4];
  if (protocol == 0xff) {
    pos = &buf[6];
    //    *(strchr(pos, '.')) = '\0';
    hydra_report(stderr, "[ERROR] %s\n", pos);
    free(buf);
    return 2;
  }
  if (protocol <= 10) {
    free(buf);
    return 2;
  }
  if (protocol > 10) {
    fprintf(stderr,
            "[INFO] This is protocol version %d, only v10 is supported, not "
            "sure if it will work\n",
            protocol);
  }
  server_version = &buf[5];
  pos = buf + strlen(server_version) + 10;
  memcpy(mysqlsalt, pos, 9);

  if (!strstr(server_version, "3.") && !strstr(server_version, "4.") && strstr(server_version, "5.")) {
#ifndef LIBMYSQLCLIENT
    hydra_report(stderr, "[ERROR] Not an MySQL protocol or unsupported version,\ncheck "
                         "configure to see if libmysql is found\n");
#endif
    free(buf);
    return 2;
  }

  free(buf);
  return 0;
}

/* prepare response to server greeting */
char *hydra_mysql_prepare_auth(char *login, char *pass) {
  unsigned char *response;
  unsigned long login_len = strlen(login) > 32 ? 32 : strlen(login);
  unsigned long response_len = 4 /* header */ + 2 /* client flags */ + 3 /* max packet len */ + login_len + 1 + 8 /* scrambled password len */;

  response = (unsigned char *)malloc(response_len + 4);
  if (response == NULL) {
    fprintf(stderr, "[ERROR] could not allocate memory\n");
    return NULL;
  }
  memset(response, 0, response_len + 4);

  *((unsigned long *)response) = response_len - 4;
  response[3] = 0x01; /* packet number */
  response[4] = 0x85;
  response[5] = 0x24;                             /* client flags */
  response[6] = response[7] = response[8] = 0x00; /* max packet */
  memcpy(&response[9], login, login_len);         /* login */
  response[9 + login_len] = '\0';                 /* null terminate login */
  hydra_scramble((char *)&response[9 + login_len + 1], mysqlsalt, pass);

  return (char *)response;
}

/* returns 0 if authentication succeed */

/* and 1 if failed                     */
char hydra_mysql_parse_response(unsigned char *response) {
  unsigned long response_len = *((unsigned long *)response) & 0xffffff;

  if (response_len < 4)
    return 0;

  if (response[4] == 0xff)
    return 1;

  return 0;
}

char hydra_mysql_send_com_quit(int32_t sock) {
  char com_quit_packet[5] = {0x01, 0x00, 0x00, 0x00, 0x01};

  hydra_send(sock, com_quit_packet, 5, 0);
  return 0;
}

int32_t start_mysql(int32_t sock, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *response = NULL, *login = NULL, *pass = NULL;
  unsigned long response_len;
  char res = 0;
  char *database = NULL;

  login = hydra_get_next_login();
  pass = hydra_get_next_password();

  if (miscptr)
    database = miscptr;

  /* read server greeting */
  res = hydra_mysql_init(sock);

  if (res == 2) {
    /* old reversing protocol trick did not work */
    /* try using the libmysql client if available */
    hydra_mysql_send_com_quit(sock);
    sock = hydra_disconnect(sock);
#ifdef LIBMYSQLCLIENT

    if (mysql == NULL) {
      mysql = mysql_init(NULL);
      if (mysql == NULL) {
        hydra_report(stderr, "[ERROR] Insufficient memory to allocate new mysql object\n");
        return 1;
      }
    }
    /*mysql_options(&mysql,MYSQL_OPT_COMPRESS,0); */
    if (!mysql_real_connect(mysql, hydra_address2string(ip), login, pass, database, port, NULL, 0)) {
      int32_t my_errno = mysql_errno(mysql);

      if (debug)
        hydra_report(stderr, "[ERROR] Failed to connect to database: %s\n", mysql_error(mysql));

      /*
         Error: 1049 SQLSTATE: 42000 (ER_BAD_DB_ERROR)
         Message: Unknown database '%s'
       */
      if (my_errno == 1049) {
        hydra_report(stderr, "[ERROR] Unknown database: %s\n", database);
      }

      if (my_errno == 1251) {
        hydra_report(stderr, "[ERROR] Client does not support authentication "
                             "protocol requested by server\n");
      }

      /*
         http://dev.mysql.com/doc/refman/5.0/en/error-messages-server.html

         Error: 1044 SQLSTATE: 42000 (ER_DBACCESS_DENIED_ERROR)
         Message: Access denied for user '%s'@'%s' to database '%s'

         Error: 1045 SQLSTATE: 28000 (ER_ACCESS_DENIED_ERROR)
         Message: Access denied for user '%s'@'%s' (using password: %s)

       */

      // if the error is more critical, we just try to reconnect
      // to the db later with the mysql_init
      if ((my_errno != 1044) && (my_errno != 1045)) {
        mysql_close(mysql);
        mysql = NULL;
      }
      return 3;
    }

    hydra_report_found_host(port, ip, "mysql", fp);
    hydra_completed_pair_found();
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0) {
      mysql_close(mysql);
      mysql = NULL;
      return 3;
    }
    return 1;
#else
    hydra_child_exit(2);
#endif
  }

  if (res == 1)
    return 1;

  /* prepare client authentication packet */
  response = hydra_mysql_prepare_auth(login, pass);
  if (response == NULL)
    return 3;
  response_len = *((unsigned long *)response) & 0xffffff;

  /* send client auth packet                                             */
  /* dunny why, mysql IO code had problem reading my response.           */
  /* When I send response_len bytes, it always read response_len-4 bytes */
  /* I fixed it just by sending 4 characters more. It is maybe not good  */
  /* coding style, but working :)                                        */
  if (hydra_send(sock, response, response_len + 4, 0) < 0) {
    free(response);
    return 1;
  }
  free(response);

  /* read authentication response */
  if ((response = hydra_mysql_receive_line(sock)) == NULL)
    return 1;
  res = hydra_mysql_parse_response((unsigned char *)response);

  if (!res) {
    hydra_mysql_send_com_quit(sock);
    sock = hydra_disconnect(sock);
    hydra_report_found_host(port, ip, "mysql", fp);
    hydra_completed_pair_found();
    free(response);
    if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
      return 3;
    return 1;
  }

  free(response);
  hydra_completed_pair();
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return 3;

  /* each try requires new connection */
  return 1;
}

void service_mysql(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
  int32_t run = 1, next_run = 1, sock = -1;
  int32_t myport = PORT_MYSQL;

  hydra_register_socket(sp);
  if (memcmp(hydra_get_next_pair(), &HYDRA_EXIT, sizeof(HYDRA_EXIT)) == 0)
    return;
  while (1) {
    switch (run) {
    case 1: /* connect and service init function */
      if (sock >= 0) {
        hydra_mysql_send_com_quit(sock);
        sock = hydra_disconnect(sock);
      }
      //      usleepn(300);
      if ((options & OPTION_SSL) == 0) {
        if (port != 0)
          myport = port;
        sock = hydra_connect_tcp(ip, myport);
        port = myport;
      }
      if (sock < 0) {
        if (quiet != 1)
          fprintf(stderr, "[ERROR] Child with pid %d terminating, can not connect\n", (int32_t)getpid());
        hydra_child_exit(1);
      }
      next_run = 2;
      break;
    case 2: /* run the cracking function */
      next_run = start_mysql(sock, ip, port, options, miscptr, fp);
      break;
    case 3: /* clean exit */
      if (sock >= 0) {
        hydra_mysql_send_com_quit(sock);
        sock = hydra_disconnect(sock);
      }
      hydra_child_exit(0);
      return;
    default:
      fprintf(stderr, "[ERROR] Caught unknown return code, exiting!\n");
      hydra_child_exit(2);
    }
    run = next_run;
  }
}

#ifndef LIBMYSQLCLIENT

#endif

/************************************************************************/

/* code belowe is copied from mysql 3.23.57 source code (www.mysql.com) */

/* and slightly modified (removed not needed parts of code, changed     */

/* data types)                                                          */

/************************************************************************/
struct hydra_rand_struct {
  unsigned long seed1, seed2, max_value;
  double max_value_dbl;
};

void hydra_randominit(struct hydra_rand_struct *rand_st, unsigned long seed1, unsigned long seed2) { /* For mysql 3.21.# */
  rand_st->max_value = 0x3FFFFFFFL;
  rand_st->max_value_dbl = (double)rand_st->max_value;
  rand_st->seed1 = seed1 % rand_st->max_value;
  rand_st->seed2 = seed2 % rand_st->max_value;
}

double hydra_rnd(struct hydra_rand_struct *rand_st) {
  rand_st->seed1 = (rand_st->seed1 * 3 + rand_st->seed2) % rand_st->max_value;
  rand_st->seed2 = (rand_st->seed1 + rand_st->seed2 + 33) % rand_st->max_value;
  return (((double)rand_st->seed1) / rand_st->max_value_dbl);
}
void hydra_hash_password(unsigned long *result, const char *password) {
  register unsigned long nr = 1345345333L, add = 7, nr2 = 0x12345671L;
  unsigned long tmp;

  for (; *password; password++) {
    if (*password == ' ' || *password == '\t')
      continue; /* skipp space in password */
    tmp = (unsigned long)(unsigned char)*password;
    nr ^= (((nr & 63) + add) * tmp) + (nr << 8);
    nr2 += (nr2 << 8) ^ nr;
    add += tmp;
  }
  result[0] = nr & (((unsigned long)1L << 31) - 1L); /* Don't use sign bit (str2int) */
  ;
  result[1] = nr2 & (((unsigned long)1L << 31) - 1L);
  return;
}

char *hydra_scramble(char *to, const char *message, const char *password) {
  struct hydra_rand_struct rand_st;
  unsigned long hash_pass[2], hash_message[2];
  char extra;

  if (password && password[0]) {
    char *to_start = to;

    hydra_hash_password(hash_pass, password);
    hydra_hash_password(hash_message, message);
    hydra_randominit(&rand_st, hash_pass[0] ^ hash_message[0], hash_pass[1] ^ hash_message[1]);
    while (*message++)
      *to++ = (char)(floor(hydra_rnd(&rand_st) * 31) + 64);
    extra = (char)(floor(hydra_rnd(&rand_st) * 31));
    while (to_start != to)
      *(to_start++) ^= extra;
  }
  *to = 0;
  return to;
}
#endif

int32_t service_mysql_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname) {
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

void usage_mysql(const char *service) {
  printf("Module mysql is optionally taking the database to attack, default is "
         "\"mysql\"\n\n");
}
