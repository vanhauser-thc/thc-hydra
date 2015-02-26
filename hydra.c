/*
 * hydra (c) 2001-2014 by van Hauser / THC <vh@thc.org>
 * http://www.thc.org
 *
 * Parallized network login hacker.
 * Don't use in military or secret service organizations, or for illegal purposes.
 *
 * License: GNU AFFERO GENERAL PUBLIC LICENSE v3.0, see LICENSE file
 */

#include "hydra.h"
#include "bfg.h"

extern void service_asterisk(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_telnet(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_ftp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_ftps(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_pop3(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_vmauthd(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_imap(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_ldap2(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_ldap3(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_ldap3_cram_md5(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_ldap3_digest_md5(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_cisco(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_cisco_enable(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_vnc(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_socks5(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_rexec(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_rlogin(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_rsh(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_nntp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_http_head(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_http_get(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_http_get_form(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_http_post_form(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_icq(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_pcnfs(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_mssql(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_cvs(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_snmp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_smtp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_smtp_enum(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_teamspeak(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_pcanywhere(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_http_proxy(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_xmpp(char *target, char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_irc(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_http_proxy_urlenum(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_s7_300(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);

// ADD NEW SERVICES HERE

#ifdef HAVE_MATH_H
extern void service_mysql(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_mysql_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
#endif
#ifdef LIBPOSTGRES
extern void service_postgres(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_postgres_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
#endif
#ifdef LIBOPENSSL
extern void service_smb(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_smb_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_oracle_listener(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_oracle_listener_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_oracle_sid(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_oracle_sid_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_sip(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_sip_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_rdp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_rdp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
#endif
#ifdef LIBSAPR3
extern void service_sapr3(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_sapr3_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
#endif
#ifdef LIBFIREBIRD
extern void service_firebird(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_firebird_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
#endif
#ifdef LIBAFP
extern void service_afp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_afp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
#endif
#ifdef LIBNCP
extern void service_ncp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_ncp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
#endif
#ifdef LIBSSH
extern void service_ssh(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_ssh_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern void service_sshkey(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_sshkey_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
#endif
#ifdef LIBSVN
extern void service_svn(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_svn_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
#endif
#ifdef LIBORACLE
extern void service_oracle(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_oracle_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
#endif

extern int service_cisco_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_cisco_enable_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_cvs_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_smtp_enum_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_http_form_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_ftp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_http_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_icq_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_imap_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_irc_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_ldap_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_mssql_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_nntp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_pcanywhere_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_pcnfs_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_pop3_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_http_proxy_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_asterisk_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_redis_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_rexec_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_rlogin_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_rsh_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_smtp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_snmp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_socks5_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_teamspeak_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_telnet_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_http_proxy_urlenum_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_vmauthd_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_vnc_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_xmpp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);
extern int service_s7_300_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port);

// ADD NEW SERVICES HERE


// ADD NEW SERVICES HERE
char *SERVICES =
  "asterisk afp cisco cisco-enable cvs firebird ftp ftps http[s]-{head|get} http[s]-{get|post}-form http-proxy http-proxy-urlenum icq imap[s] irc ldap2[s] ldap3[-{cram|digest}md5][s] mssql mysql ncp nntp oracle oracle-listener oracle-sid pcanywhere pcnfs pop3[s] postgres rdp redis rexec rlogin rsh s7-300 sapr3 sip smb smtp[s] smtp-enum snmp socks5 ssh sshkey svn teamspeak telnet[s] vmauthd vnc xmpp";

#define MAXBUF       520
#define MAXLINESIZE  ( ( MAXBUF / 2 ) - 4 )
#define MAXTASKS     64
#define MAXSERVERS   16
#define MAXFAIL      3
#define MAXENDWAIT   20
#define WAITTIME     32
#define TASKS        16
#define SKIPLOGIN    256
#define USLEEP_LOOP  10
#define MAX_LINES    50000000   // 50 millions, do not put more than 65millions
#define MAX_BYTES    500000000  // 500 millions, do not put more than 650millions

#define RESTOREFILE "./hydra.restore"

#define PROGRAM   "Hydra"
#define VERSION   "v8.2-dev"
#define AUTHOR    "van Hauser/THC"
#define EMAIL     "<vh@thc.org>"
#define RESOURCE  "http://www.thc.org/thc-hydra"

extern char *hydra_strcasestr(const char *haystack, const char *needle);
extern void hydra_tobase64(unsigned char *buf, int buflen, int bufsize);
extern char *hydra_string_replace(const char *string, const char *substr, const char *replacement);
extern char *hydra_address2string(char *address);
extern int colored_output;
extern char quiet;
extern int do_retry;

void hydra_kill_head(int head_no, int killit, int fail);

// some structure definitions
typedef struct {
  pid_t pid;
  int sp[2];
  int target_no;
  char *current_login_ptr;
  char *current_pass_ptr;
  char reverse[256];
  int active;
  int redo;
  time_t last_seen;
} hydra_head;

typedef struct {
  char *target;
  char ip[36];
  char *login_ptr;
  char *pass_ptr;
  unsigned long int login_no;
  unsigned long int pass_no;
  unsigned long int sent;
  int pass_state;
  int use_count;
  int done;                     // 0 if active, 1 if finished scanning, 2 if error (for RESTOREFILE), 3 could not be resolved
  int fail_count;
  int redo_state;
  int redo;
  int ok;
  int failed;
  int skipcnt;
  int port;
  char *redo_login[MAXTASKS * 2 + 2];
  char *redo_pass[MAXTASKS * 2 + 2];
  char *skiplogin[SKIPLOGIN];
//  char *bfg_ptr[MAXTASKS];
} hydra_target;

typedef struct {
  int active;                   // active tasks of hydra_options.max_use
  int targets;
  int finished;
  int exit;
  unsigned long int todo_all;
  unsigned long int todo;
  unsigned long int sent;
  unsigned long int found;
  unsigned long int countlogin;
  unsigned long int countpass;
  size_t sizelogin;
  size_t sizepass;
  FILE *ofp;
} hydra_brain;

typedef struct {
  int mode;                     // valid modes: 0 = -l -p, 1 = -l -P, 2 = -L -p, 3 = -L -P, 4 = -l -x, 6 = -L -x, +8 if -e r, +16 if -e n, +32 if -e s, 64 = -C | bit 128 undefined
  int loop_mode;                // valid modes: 0 = password, 1 = user
  int ssl;
  int restore;
  int debug;                    // is external - for restore 
  int verbose;                  // is external - for restore 
  int showAttempt;
  int tasks;
  int try_null_password;
  int try_password_same_as_login;
  int try_password_reverse_login;
  int exit_found;
  int max_use;
  int cidr;
  char *login;
  char *loginfile;
  char *pass;
  char *passfile;
  char *outfile_ptr;
  char *infile_ptr;
  char *colonfile;
  int waittime;                 // is external - for restore 
  int conwait;                  // is external - for restore 
  unsigned int port;            // is external - for restore 
  char *miscptr;
  char *server;
  char *service;
  char bfg;
} hydra_option;

typedef struct {
  char *name;
  int port;
  int port_ssl;
} hydra_portlist;

// external vars 
extern char HYDRA_EXIT[5];

#if !defined(ANDROID) && !defined(__BIONIC__)
extern int errno;
#endif
extern int debug;
extern int verbose;
extern int waittime;
extern int port;
extern int found;
extern int use_proxy;
extern int proxy_string_port;
extern char proxy_string_ip[36];
extern char proxy_string_type[10];
extern char *proxy_authentication;
extern char *cmdlinetarget;
extern char *fe80;

// required global vars 
char *prg;
size_t size_of_data = -1;
hydra_head **hydra_heads = NULL;
hydra_target **hydra_targets = NULL;
hydra_option hydra_options;
hydra_brain hydra_brains;
char *sck = NULL;
int prefer_ipv6 = 0, conwait = 0, loop_cnt = 0, fck = 0, options = 0, killed = 0;
int child_head_no = -1, child_socket;

// moved for restore feature 
int process_restore = 0, dont_unlink;
char *login_ptr = NULL, *pass_ptr = "", *csv_ptr = NULL, *servers_ptr = NULL;
size_t countservers = 1, sizeservers = 0;
char empty_login[2] = "", unsupported[500] = "";

// required to save stack memory
char snpbuf[MAXBUF];
int snpdone, snp_is_redo, snpbuflen, snpi, snpj, snpdont;

#include "performance.h"

void help(int ext) {
  printf("Syntax: hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e nsr]" " [-o FILE] [-t TASKS] [-M FILE [-T TASKS]] [-w TIME] [-W TIME] [-f] [-s PORT]"
#ifdef HAVE_MATH_H
         " [-x MIN:MAX:CHARSET]"
#endif
         " [-SuvVd46] "
         //"[server service [OPT]]|"
         "[service://server[:PORT][/OPT]]\n");
  printf("\nOptions:\n");
  if (ext)
    printf("  -R        restore a previous aborted/crashed session\n");
#ifdef LIBOPENSSL
  if (ext)
    printf("  -S        perform an SSL connect\n");
#endif
  if (ext)
    printf("  -s PORT   if the service is on a different default port, define it here\n");
  printf("  -l LOGIN or -L FILE  login with LOGIN name, or load several logins from FILE\n");
  printf("  -p PASS  or -P FILE  try password PASS, or load several passwords from FILE\n");
#ifdef HAVE_MATH_H
  if (ext)
    printf("  -x MIN:MAX:CHARSET  password bruteforce generation, type \"-x -h\" to get help\n");
#endif
  if (ext)
    printf("  -e nsr    try \"n\" null password, \"s\" login as pass and/or \"r\" reversed login\n");
  if (ext)
    printf("  -u        loop around users, not passwords (effective! implied with -x)\n");
  printf("  -C FILE   colon separated \"login:pass\" format, instead of -L/-P options\n");
  printf("  -M FILE   list of servers to attack, one entry per line, ':' to specify port\n");
  if (ext)
    printf("  -o FILE   write found login/password pairs to FILE instead of stdout\n");
  if (ext)
    printf("  -f / -F   exit when a login/pass pair is found (-M: -f per host, -F global)\n");
  printf("  -t TASKS  run TASKS number of connects in parallel (per host, default: %d)\n", TASKS);
  if (ext)
    printf("  -w / -W TIME  waittime for responses (%ds) / between connects per thread\n", WAITTIME);
  if (ext)
    printf("  -4 / -6   use IPv4 (default) / IPv6 addresses (put always in [] also in -M)\n");
  if (ext)
    printf("  -v / -V / -d  verbose mode / show login+pass for each attempt / debug mode \n");
  if (ext)
    printf("  -q        do not print messages about connection erros\n");
  printf("  -U        service module usage details\n");
  if (ext == 0)
    printf("  -h        more command line options (COMPLETE HELP)\n");
  printf("  server    the target: DNS, IP or 192.168.0.0/24 (this OR the -M option)\n");
  printf("  service   the service to crack (see below for supported protocols)\n");
  printf("  OPT       some service modules support additional input (-U for module help)\n");

  printf("\nSupported services: %s\n", SERVICES);
  printf("\n%s is a tool to guess/crack valid login/password pairs. Licensed under AGPL\nv3.0. The newest version is always available at %s\n", PROGRAM, RESOURCE);
  printf("Don't use in military or secret service organizations, or for illegal purposes.\n");
  if (ext && strlen(unsupported) > 0) {
    if (unsupported[strlen(unsupported) - 1] == ' ')
      unsupported[strlen(unsupported) - 1] = 0;
    printf("These services were not compiled in: %s.\n", unsupported);
  }
  if (ext) {
    printf("\nUse HYDRA_PROXY_HTTP or HYDRA_PROXY - and if needed HYDRA_PROXY_AUTH - environment for a proxy setup.\n");
    printf("E.g.:  %% export HYDRA_PROXY=socks5://127.0.0.1:9150 (or socks4:// or connect://)\n");
    printf("       %% export HYDRA_PROXY_HTTP=http://proxy:8080\n");
    printf("       %% export HYDRA_PROXY_AUTH=user:pass\n");
  }

  printf("\nExample%s:%s  hydra -l user -P passlist.txt ftp://192.168.0.1\n", ext == 0 ? "" : "s", ext == 0 ? "" : "\n");
  if (ext) {
    printf("  hydra -L userlist.txt -p defaultpw imap://192.168.0.1/PLAIN\n");
    printf("  hydra -C defaults.txt -6 pop3s://[2001:db8::1]:143/TLS:DIGEST-MD5\n");
    printf("  hydra -l admin -p password ftp://[192.168.0.0/24]/\n");
    printf("  hydra -L logins.txt -P pws.txt -M targets.txt ssh\n");
  }
  exit(-1);
}

void help_bfg() {
  printf("Hydra bruteforce password generation option usage:\n\n"
         "  -x MIN:MAX:CHARSET\n\n"
         "     MIN     is the minimum number of characters in the password\n"
         "     MAX     is the maximum number of characters in the password\n"
         "     CHARSET is a specification of the characters to use in the generation\n"
         "             valid CHARSET values are: 'a' for lowercase letters,\n"
         "             'A' for uppercase letters, '1' for numbers, and for all others,\n"
         "             just add their real representation.\n\n"
         "Examples:\n"
         "   -x 3:5:a  generate passwords from length 3 to 5 with all lowercase letters\n"
         "   -x 5:8:A1 generate passwords from length 5 to 8 with uppercase and numbers\n"
         "   -x 1:3:/  generate passwords from length 1 to 3 containing only slashes\n" "   -x 5:5:/%%,.-  generate passwords with length 5 which consists only of /%%,.-\n");
  printf("\nThe bruteforce mode was made by Jan Dlabal, http://houbysoft.com/bfg/\n");
  exit(-1);
}

void module_usage() {
  int find = 0;

  if (hydra_options.service) {
    printf("\nHelp for module %s:\n============================================================================\n", hydra_options.service);
    if ((strcmp(hydra_options.service, "oracle") == 0) || (strcmp(hydra_options.service, "ora") == 0)) {
      printf("Module oracle / ora is optionally taking the ORACLE SID, default is \"ORCL\"\n\n");
      find = 1;
    }
    if ((strcmp(hydra_options.service, "oracle-listener") == 0) || (strcmp(hydra_options.service, "tns") == 0)) {
      printf("Module oracle-listener / tns is optionally taking the mode the password is stored as, could be PLAIN (default) or CLEAR\n\n");
      find = 1;
    }
    if (strcmp(hydra_options.service, "cvs") == 0) {
      printf("Module cvs is optionally taking the repository name to attack, default is \"/root\"\n\n");
      find = 1;
    }
    if (strcmp(hydra_options.service, "xmpp") == 0) {
      printf("Module xmpp is optionally taking one authentication type of:\n"
             "  LOGIN (default), PLAIN, CRAM-MD5, DIGEST-MD5, SCRAM-SHA1\n\n"
             "Note, the target passed should be a fdqn as the value is used in the Jabber init request, example: hermes.jabber.org\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "pop3") == 0)) {
      printf("Module pop3 is optionally taking one authentication type of:\n"
             "  CLEAR (default), LOGIN, PLAIN, CRAM-MD5, CRAM-SHA1,\n"
             "  CRAM-SHA256, DIGEST-MD5, NTLM.\n" "Additionally TLS encryption via STLS can be enforced with the TLS option.\n\n" "Example: pop3://target/TLS:PLAIN\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "rdp") == 0)) {
      printf("Module rdp is optionally taking the windows domain name.\n" "For example:\nhydra rdp://192.168.0.1/firstdomainname -l john -p doe\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "s7-300") == 0)) {
      printf("Module S7-300 is for a special Siemens PLC. It either requires only a password or no authentication, so just use the -p or -P option.\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "nntp") == 0)) {
      printf("Module nntp is optionally taking one authentication type of:\n" "  USER (default), LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5, NTLM\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "imap") == 0)) {
      printf("Module imap is optionally taking one authentication type of:\n"
             "  CLEAR or APOP (default), LOGIN, PLAIN, CRAM-MD5, CRAM-SHA1,\n"
             "  CRAM-SHA256, DIGEST-MD5, NTLM\n" "Additionally TLS encryption via STARTTLS can be enforced with the TLS option.\n\n" "Example: imap://target/TLS:PLAIN\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "smtp-enum")) == 0) {
      printf("Module smtp-enum is optionally taking one SMTP command of:\n\n"
             "VRFY (default), EXPN, RCPT (which will connect using \"root\" account)\n"
             "login parameter is used as username and password parameter as the domain name\n"
             "For example to test if john@localhost exists on 192.168.0.1:\n" "hydra smtp-enum://192.168.0.1/vrfy -l john -p localhost\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "smtp")) == 0) {
      printf("Module smtp is optionally taking one authentication type of:\n"
             "  LOGIN (default), PLAIN, CRAM-MD5, DIGEST-MD5, NTLM\n\n"
             "Additionally TLS encryption via STARTTLS can be enforced with the TLS option.\n\n" "Example: smtp://target/TLS:PLAIN\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "svn") == 0)) {
      printf("Module svn is optionally taking the repository name to attack, default is \"trunk\"\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "ncp") == 0)) {
      printf("Module ncp is optionally taking the full context, for example \".O=cx\"\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "firebird") == 0)) {
      printf("Module firebird is optionally taking the database path to attack,\n" "default is \"C:\\Program Files\\Firebird\\Firebird_1_5\\security.fdb\"\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "mysql") == 0)) {
      printf("Module mysql is optionally taking the database to attack, default is \"mysql\"\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "irc") == 0)) {
      printf("Module irc is optionally taking the general server password, if the server is requiring one\n" "and none is passed the password from -p/-P will be used\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "postgres") == 0)) {
      printf("Module postgres is optionally taking the database to attack, default is \"template1\"\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "telnet") == 0)) {
      printf("Module telnet is optionally taking the string which is displayed after\n"
             "a successful login (case insensitive), use if the default in the telnet\n" "module produces too many false positives\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "sapr3") == 0)) {
      printf("Module sapr3 requires the client id, a number between 0 and 99\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "sshkey") == 0)) {
      printf("Module sshkey does not provide additional options, although the semantic for\n"
             "options -p and -P is changed:\n"
             "  -p expects a path to an unencrypted private key in PEM format.\n"
             "  -P expects a filename containing a list of path to some unencrypted\n" "     private keys in PEM format.\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "cisco-enable") == 0)) {
      printf("Module cisco-enable is optionally taking the logon password for the cisco device\n"
             "Note: if AAA authentication is used, use the -l option for the username\n"
             "and the optional parameter for the password of the user.\n"
             "Examples:\n"
             "  hydra -P pass.txt target cisco-enable  (direct console access)\n"
             "  hydra -P pass.txt -m cisco target cisco-enable  (Logon password cisco)\n"
             "  hydra -l foo -m bar -P pass.txt target cisco-enable  (AAA Login foo, password bar)\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "cisco") == 0)) {
      printf("Module cisco is optionally taking the keyword ENTER, it then sends an initial\n" "ENTER when connecting to the service.\n");
      find = 1;
    }
    if (!find && ((strcmp(hydra_options.service, "ldap2") == 0)
                  || (strcmp(hydra_options.service, "ldap3") == 0)
                  || (strcmp(hydra_options.service, "ldap3-crammd5") == 0)
                  || (strcmp(hydra_options.service, "ldap3-digestmd5") == 0))
      ) {
      printf("Module %s is optionally taking the DN (depending of the auth method choosed\n"
             "Note: you can also specify the DN as login when Simple auth method is used).\n"
             "The keyword \"^USER^\" is replaced with the login.\n"
             "Special notes for Simple method has 3 operation modes: anonymous, (no user no pass),\n"
             "unauthenticated (user but no pass), user/pass authenticated (user and pass).\n"
             "So don't forget to set empty string as user/pass to test all modes.\n"
             "Hint: to authenticate to a windows active directy ldap, this is usually\n"
             " cn=^USER^,cn=users,dc=foo,dc=bar,dc=com for domain foo.bar.com\n\n", hydra_options.service);
      find = 1;
    }
    if (!find && ((strcmp(hydra_options.service, "smb") == 0) || (strcmp(hydra_options.service, "smbnt") == 0))) {
      printf("Module smb default value is set to test both local and domain account, using a simple password with NTLM dialect.\n"
             "Note: you can set the group type using LOCAL or DOMAIN keyword\n"
             "      or other_domain:{value} to specify a trusted domain.\n"
             "      you can set the password type using HASH or MACHINE keyword\n"
             "      (to use the Machine's NetBIOS name as the password).\n"
             "      you can set the dialect using NTLMV2, NTLM, LMV2, LM keyword.\n"
             "Example: \n"
             "      hydra smb://microsoft.com  -l admin -p tooeasy -m \"local lmv2\"\n"
             "      hydra smb://microsoft.com  -l admin -p D5731CFC6C2A069C21FD0D49CAEBC9EA:2126EE7712D37E265FD63F2C84D2B13D::: -m \"local hash\"\n"
             "      hydra smb://microsoft.com  -l admin -p tooeasy -m \"other_domain:SECONDDOMAIN\"\n\n");
      find = 1;
    }
    if (!find && ((strcmp(hydra_options.service, "http-get-form") == 0)
                  || (strcmp(hydra_options.service, "https-get-form") == 0)
                  || (strcmp(hydra_options.service, "http-post-form") == 0)
                  || (strcmp(hydra_options.service, "https-post-form") == 0)
                  || (strncmp(hydra_options.service, "http-form", 9) == 0)
                  || (strncmp(hydra_options.service, "https-form", 10) == 0)
        )
      ) {
      printf("Module %s requires the page and the parameters for the web form.\n\n"
             "By default this module is configured to follow a maximum of 5 redirections in\n"
             "a row. It always gathers a new cookie from the same URL without variables\n"
             "The parameters take three \":\" separated values, plus optional values.\n"
             "(Note: if you need a colon in the option string as value, escape it with \"\\:\", but do not escape a \"\\\" with \"\\\\\".)\n"
             "\nSyntax:   <url>:<form parameters>:<condition string>[:<optional>[:<optional>]\n"
             "First is the page on the server to GET or POST to (URL).\n"
             "Second is the POST/GET variables (taken from either the browser, proxy, etc.\n"
             " with usernames and passwords being replaced in the \"^USER^\" and \"^PASS^\"\n"
             " placeholders (FORM PARAMETERS)\n"
             "Third is the string that it checks for an *invalid* login (by default)\n"
             " Invalid condition login check can be preceded by \"F=\", successful condition\n"
             " login check must be preceded by \"S=\".\n"
             " This is where most people get it wrong. You have to check the webapp what a\n"
             " failed string looks like and put it in this parameter!\n"
             "The following parameters are optional:\n"
             " C=/page/uri     to define a different page to gather initial cookies from\n"
             " (h|H)=My-Hdr\\: foo   to send a user defined HTTP header with each request\n"
             "                 ^USER^ and ^PASS^ can also be put into these headers!\n"
             "                 Note: 'h' will add the user-defined header at the end\n"
             "                 regardless it's already being sent by Hydra or not.\n"
             "                 'H' will replace the value of that header if it exists, by the\n"
             "                 one supplied by the user, or add the header at the end\n"
             "Note that if you are going to put colons (:) in your headers you should escape them with a backslash (\\).\n"
             " All colons that are not option separators should be escaped (see the examples above and below).\n"
             " You can specify a header without escaping the colons, but that way you will not be able to put colons\n"
             " in the header value itself, as they will be interpreted by hydra as option separators.\n"
             "\nExamples:\n"
             " \"/login.php:user=^USER^&pass=^PASS^:incorrect\"\n"
             " \"/login.php:user=^USER^&pass=^PASS^&colon=colon\\:escape:S=authlog=.*success\"\n"
             " \"/login.php:user=^USER^&pass=^PASS^&mid=123:authlog=.*failed\"\n"
             " \"/:user=^USER&pass=^PASS^:failed:H=Authorization\\: Basic dT1w:H=Cookie\\: sessid=aaaa:h=X-User\\: ^USER^\"\n"
             " \"/exchweb/bin/auth/owaauth.dll:destination=http%%3A%%2F%%2F<target>%%2Fexchange&flags=0&username=<domain>%%5C^USER^&password=^PASS^&SubmitCreds=x&trusted=0:reason=:C=/exchweb\"\n",
             hydra_options.service);
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "http-proxy") == 0)) {
      printf("Module http-proxy is optionally taking the page to authenticate at.\n"
             "Default is http://www.microsoft.com/)\n" "Basic, DIGEST-MD5 and NTLM are supported and negotiated automatically.\n\n");
      find = 1;
    }
    if (!find && (strcmp(hydra_options.service, "http-proxy-urlenum") == 0)) {
      printf("Module http-proxy-urlenum only uses the -L option, not -x or -p/-P option.\n"
             "The -L loginfile must contain the URL list to try through the proxy.\n"
             "The proxy credentials cann be put as the optional parameter, e.g.\n"
             "   hydra -L urllist.txt -s 3128 target.com http-proxy-urlenum user:pass\n" "   hydra -L urllist.txt http-proxy-urlenum://target.com:3128/user:pass\n\n");
      find = 1;
    }
    if (!find && (strncmp(hydra_options.service, "snmp", 4) == 0)) {
      printf("Module snmp is optionally taking the following parameters:\n");
      printf("   READ  perform read requests (default)\n");
      printf("   WRITE perform write requests\n");
      printf("   1     use SNMP version 1 (default)\n");
      printf("   2     use SNMP version 2\n");
      printf("   3     use SNMP version 3\n");
      printf("           Note that SNMP version 3 usually uses both login and passwords!\n");
      printf("           SNMP version 3 has the following optional sub parameters:\n");
      printf("             MD5   use MD5 authentication (default)\n");
      printf("             SHA   use SHA authentication\n");
      printf("             DES   use DES encryption\n");
      printf("             AES   use AES encryption\n");
      printf("           if no -p/-P parameter is given, SNMPv3 noauth is performed, which\n");
      printf("           only requires a password (or username) not both.\n");
      printf("To combine the options, use colons (\":\"), e.g.:\n");
      printf("   hydra -L user.txt -P pass.txt -m 3:SHA:AES:READ target.com snmp\n");
      printf("   hydra -P pass.txt -m 2 target.com snmp\n");
      find = 1;
    }
    if (!find && ((strcmp(hydra_options.service, "http-get") == 0)
                  || (strcmp(hydra_options.service, "https-get") == 0)
                  || (strcmp(hydra_options.service, "http-post") == 0)
                  || (strcmp(hydra_options.service, "https-post") == 0))
      ) {
      printf("Module %s requires the page to authenticate.\n"
             "For example:  \"/secret\" or \"http://bla.com/foo/bar\" or \"https://test.com:8080/members\"\n\n", hydra_options.service);
      find = 1;
    }
  }
  if (!find)                    // this is also printed if the module does not exist at all
    printf("The Module %s does not need or support optional parameters\n", hydra_options.service);
  exit(0);
}

void hydra_debug(int force, char *string) {
  int i;

  if (!debug && !force)
    return;

  printf("[DEBUG] Code: %s   Time: %lu\n", string, (unsigned long int) time(NULL));
  printf("[DEBUG] Options: mode %d  ssl %d  restore %d  showAttempt %d  tasks %d  max_use %d tnp %d  tpsal %d  tprl %d  exit_found %d  miscptr %s  service %s\n",
         hydra_options.mode, hydra_options.ssl, hydra_options.restore, hydra_options.showAttempt, hydra_options.tasks, hydra_options.max_use,
         hydra_options.try_null_password, hydra_options.try_password_same_as_login, hydra_options.try_password_reverse_login, hydra_options.exit_found,
         hydra_options.miscptr == NULL ? "(null)" : hydra_options.miscptr, hydra_options.service);
  printf("[DEBUG] Brains: active %d  targets %d  finished %d  todo_all %lu  todo %lu  sent %lu  found %lu  countlogin %lu  sizelogin %lu  countpass %lu  sizepass %lu\n",
         hydra_brains.active, hydra_brains.targets, hydra_brains.finished, hydra_brains.todo_all, hydra_brains.todo, hydra_brains.sent, hydra_brains.found,
         (unsigned long int) hydra_brains.countlogin, (unsigned long int) hydra_brains.sizelogin, (unsigned long int) hydra_brains.countpass,
         (unsigned long int) hydra_brains.sizepass);
  for (i = 0; i < hydra_brains.targets; i++)
    printf
      ("[DEBUG] Target %d - target %s  ip %s  login_no %lu  pass_no %lu  sent %lu  pass_state %d  use_count %d  failed %d  done %d  fail_count %d  login_ptr %s  pass_ptr %s\n",
       i, hydra_targets[i]->target == NULL ? "(null)" : hydra_targets[i]->target, hydra_address2string(hydra_targets[i]->ip), hydra_targets[i]->login_no,
       hydra_targets[i]->pass_no, hydra_targets[i]->sent, hydra_targets[i]->pass_state, hydra_targets[i]->use_count, hydra_targets[i]->failed, hydra_targets[i]->done,
       hydra_targets[i]->fail_count, hydra_targets[i]->login_ptr == NULL ? "(null)" : hydra_targets[i]->login_ptr,
       hydra_targets[i]->pass_ptr == NULL ? "(null)" : hydra_targets[i]->pass_ptr);
  if (hydra_heads != NULL)
    for (i = 0; i < hydra_options.max_use; i++)
      printf("[DEBUG] Task %d - pid %d  active %d  redo %d  current_login_ptr %s  current_pass_ptr %s\n",
             i, (int) hydra_heads[i]->pid, hydra_heads[i]->active, hydra_heads[i]->redo,
             hydra_heads[i]->current_login_ptr == NULL ? "(null)" : hydra_heads[i]->current_login_ptr,
             hydra_heads[i]->current_pass_ptr == NULL ? "(null)" : hydra_heads[i]->current_pass_ptr);
}

void bail(char *text) {
  fprintf(stderr, "[ERROR] %s\n", text);
  exit(-1);
}

void hydra_restore_write(int print_msg) {
  FILE *f;
  hydra_brain brain;
  char mynull[4] = { 0, 0, 0, 0 };
  int i = 0, j = 0;
  hydra_head hh;

  if (process_restore != 1)
    return;

  for (i = 0; i < hydra_brains.targets; i++)
    if (hydra_targets[j]->done != 1 && hydra_targets[j]->done != 3)
      j++;
  if (j == 0) {
    process_restore = 0;
    return;
  }

  if ((f = fopen(RESTOREFILE, "w")) == NULL) {
    fprintf(stderr, "[ERROR] Can not create restore file (%s) - \n", RESTOREFILE);
    perror("");
    process_restore = 0;
    return;
  } else if (debug)
    printf("[DEBUG] Writing restore file... ");

  fprintf(f, "%s\n", PROGRAM);
  memcpy(&brain, &hydra_brains, sizeof(hydra_brain));
  brain.targets = i;
  brain.ofp = NULL;
  brain.finished = brain.active = 0;
  fck = fwrite(&bf_options, sizeof(bf_options), 1, f);
  if (bf_options.crs != NULL)
    fck = fwrite(bf_options.crs, BF_CHARSMAX, 1, f);
  else
    fck = fwrite(mynull, sizeof(mynull), 1, f);
  fck = fwrite(&brain, sizeof(hydra_brain), 1, f);
  fck = fwrite(&hydra_options, sizeof(hydra_option), 1, f);
  fprintf(f, "%s\n", hydra_options.server == NULL ? "" : hydra_options.server);
  if (hydra_options.outfile_ptr == NULL)
    fprintf(f, "\n");
  else
    fprintf(f, "%s\n", hydra_options.outfile_ptr);
  fprintf(f, "%s\n%s\n", hydra_options.miscptr == NULL ? "" : hydra_options.miscptr, hydra_options.service);
  fck = fwrite(login_ptr, hydra_brains.sizelogin, 1, f);
  if (hydra_options.colonfile == NULL || hydra_options.colonfile == empty_login)
    fck = fwrite(pass_ptr, hydra_brains.sizepass, 1, f);
  for (j = 0; j < hydra_brains.targets; j++)
    if (hydra_targets[j]->done != 1) {
      fck = fwrite(hydra_targets[j], sizeof(hydra_target), 1, f);
      fprintf(f, "%s\n%d\n%d\n", hydra_targets[j]->target == NULL ? "" : hydra_targets[j]->target, (int) (hydra_targets[j]->login_ptr - login_ptr),
              (int) (hydra_targets[j]->pass_ptr - pass_ptr));
      fprintf(f, "%s\n%s\n", hydra_targets[j]->login_ptr, hydra_targets[j]->pass_ptr);
      if (hydra_targets[j]->redo)
        for (i = 0; i < hydra_targets[j]->redo; i++)
          fprintf(f, "%s\n%s\n", hydra_targets[j]->redo_login[i], hydra_targets[j]->redo_pass[i]);
      if (hydra_targets[j]->skipcnt)
        for (i = 0; i < hydra_targets[j]->skipcnt; i++)
          fprintf(f, "%s\n", hydra_targets[j]->skiplogin[i]);
    }
  for (j = 0; j < hydra_options.max_use; j++) {
    memcpy((char *) &hh, hydra_heads[j], sizeof(hydra_head));
    if (j == 0 && debug) {
      printf("[DEBUG] sizeof hydra_head: %d\n", sizeof(hydra_head));
      printf("[DEBUG] memcmp: %d\n", memcmp(hydra_heads[j], &hh, sizeof(hydra_head)));
    }
    hh.active = 0;              // re-enable disabled heads
    if ((hh.current_login_ptr != NULL && hh.current_login_ptr != empty_login)
        || (hh.current_pass_ptr != NULL && hh.current_pass_ptr != empty_login)) {
      hh.redo = 1;
      if (print_msg && debug)
        printf("[DEBUG] we will redo the following combination: target %s  login \"%s\"  pass \"%s\"\n", hydra_targets[hh.target_no]->target,
               hh.current_login_ptr, hh.current_pass_ptr);
    }
    fck = fwrite((char *) &hh, sizeof(hydra_head), 1, f);
    if (hh.redo /* && (hydra_options.bfg == 0 || (hh.current_pass_ptr == hydra_targets[hh.target_no]->bfg_ptr[j] && isprint((char) hh.current_pass_ptr[0]))) */ )
      fprintf(f, "%s\n%s\n", hh.current_login_ptr == NULL ? "" : hh.current_login_ptr, hh.current_pass_ptr == NULL ? "" : hh.current_pass_ptr);
    else
      fprintf(f, "\n\n");
  }

  fprintf(f, "%s\n", PROGRAM);
  fclose(f);
  if (debug)
    printf("done\n");
  if (print_msg)
    printf("The session file ./hydra.restore was written. Type \"hydra -R\" to resume session.\n");
  hydra_debug(0, "hydra_restore_write()");
}

void hydra_restore_read() {
  FILE *f;
  char mynull[4];
  int i, j, orig_debug = debug;
  char out[1024];

  if (debug) printf("[DEBUG] reading restore file %s\n", RESTOREFILE);
  if ((f = fopen(RESTOREFILE, "r")) == NULL) {
    fprintf(stderr, "[ERROR] restore file (%s) not found - ", RESTOREFILE);
    perror("");
    exit(-1);
  }

  sck = fgets(out, sizeof(out), f);
  if (out[0] != 0 && out[strlen(out) - 1] == '\n')
    out[strlen(out) - 1] = 0;
  if (strcmp(out, PROGRAM) != 0) {
    fprintf(stderr, "[ERROR] invalid restore file (begin)\n");
    exit(-1);
  }
  fck = (int) fread(&bf_options, sizeof(bf_options), 1, f);
  fck = (int) fread(mynull, sizeof(mynull), 1, f);
  if (debug) printf("[DEBUG] reading restore file: Step 1 complete\n");
  if (mynull[0] + mynull[1] + mynull[2] + mynull[3] == 0) {
    bf_options.crs = NULL;
  } else {
    bf_options.crs = malloc(BF_CHARSMAX);
    memcpy(bf_options.crs, mynull, sizeof(mynull));
    fck = fread(bf_options.crs + sizeof(mynull), BF_CHARSMAX - sizeof(mynull), 1, f);
  }
  if (debug) printf("[DEBUG] reading restore file: Step 2 complete\n");

  fck = (int) fread(&hydra_brains, sizeof(hydra_brain), 1, f);
  hydra_brains.ofp = stdout;
  fck = (int) fread(&hydra_options, sizeof(hydra_option), 1, f);
  hydra_options.restore = 1;
  verbose = hydra_options.verbose;
  debug = hydra_options.debug;
  if (debug || orig_debug) printf("[DEBUG] run_debug %d, orig_debug %d\n", debug, orig_debug);
  if (orig_debug) {
    debug = 1;
    hydra_options.debug = 1;
  }
  waittime = hydra_options.waittime;
  conwait = hydra_options.conwait;
  port = hydra_options.port;
  sck = fgets(out, sizeof(out), f);
  if (out[0] != 0 && out[strlen(out) - 1] == '\n')
    out[strlen(out) - 1] = 0;
  hydra_options.server = strdup(out);
  sck = fgets(out, sizeof(out), f);
  if (out[0] != 0 && out[strlen(out) - 1] == '\n')
    out[strlen(out) - 1] = 0;
  if (debug) printf("[DEBUG] reading restore file: Step 3 complete\n");
  if (strlen(out) > 0) {
    hydra_options.outfile_ptr = malloc(strlen(out) + 1);
    strcpy(hydra_options.outfile_ptr, out);
  } else
    hydra_options.outfile_ptr = NULL;
  if (debug) printf("[DEBUG] reading restore file: Step 4 complete\n");
  sck = fgets(out, sizeof(out), f);
  if (out[0] != 0 && out[strlen(out) - 1] == '\n')
    out[strlen(out) - 1] = 0;
  if (debug) printf("[DEBUG] reading restore file: Step 5 complete\n");
  if (strlen(out) == 0)
    hydra_options.miscptr = NULL;
  else {
    hydra_options.miscptr = malloc(strlen(out) + 1);
    strcpy(hydra_options.miscptr, out);
  }
  if (debug) printf("[DEBUG] reading restore file: Step 6 complete\n");
  sck = fgets(out, sizeof(out), f);
  if (out[0] != 0 && out[strlen(out) - 1] == '\n')
    out[strlen(out) - 1] = 0;
  if (debug) printf("[DEBUG] reading restore file: Step 7 complete\n");
  hydra_options.service = malloc(strlen(out) + 1);
  strcpy(hydra_options.service, out);
  if (debug) printf("[DEBUG] reading restore file: Step 8 complete\n");

  login_ptr = malloc(hydra_brains.sizelogin);
  fck = (int) fread(login_ptr, hydra_brains.sizelogin, 1, f);
  if (debug) printf("[DEBUG] reading restore file: Step 9 complete\n");
  if ((hydra_options.mode & 64) != 64) {        // NOT colonfile mode
    pass_ptr = malloc(hydra_brains.sizepass);
    fck = (int) fread(pass_ptr, hydra_brains.sizepass, 1, f);
  } else {                      // colonfile mode 
    hydra_options.colonfile = empty_login;      // dummy 
    pass_ptr = csv_ptr = login_ptr;
  }
  if (debug) printf("[DEBUG] reading restore file: Step 10 complete\n");

  hydra_targets = malloc((hydra_brains.targets + 3) * sizeof(hydra_targets));
  for (j = 0; j < hydra_brains.targets; j++) {
    hydra_targets[j] = malloc(sizeof(hydra_target));
    fck = (int) fread(hydra_targets[j], sizeof(hydra_target), 1, f);
    sck = fgets(out, sizeof(out), f);
    if (out[0] != 0 && out[strlen(out) - 1] == '\n')
      out[strlen(out) - 1] = 0;
    hydra_targets[j]->target = malloc(strlen(out) + 1);
    strcpy(hydra_targets[j]->target, out);
    sck = fgets(out, sizeof(out), f);
    hydra_targets[j]->login_ptr = login_ptr + atoi(out);
    sck = fgets(out, sizeof(out), f);
    hydra_targets[j]->pass_ptr = pass_ptr + atoi(out);
    sck = fgets(out, sizeof(out), f);   // target login_ptr, ignord
    sck = fgets(out, sizeof(out), f);
    if (hydra_options.bfg) {
      if (out[0] != 0 && out[strlen(out) - 1] == '\n')
        out[strlen(out) - 1] = 0;
      hydra_targets[j]->pass_ptr = malloc(strlen(out) + 1);
      strcpy(hydra_targets[j]->pass_ptr, out);
    }
    if (hydra_targets[j]->redo > 0)
      for (i = 0; i < hydra_targets[j]->redo; i++) {
        sck = fgets(out, sizeof(out), f);
        if (out[0] != 0 && out[strlen(out) - 1] == '\n')
          out[strlen(out) - 1] = 0;
        hydra_targets[j]->redo_login[i] = malloc(strlen(out) + 1);
        strcpy(hydra_targets[j]->redo_login[i], out);
        sck = fgets(out, sizeof(out), f);
        if (out[0] != 0 && out[strlen(out) - 1] == '\n')
          out[strlen(out) - 1] = 0;
        hydra_targets[j]->redo_pass[i] = malloc(strlen(out) + 1);
        strcpy(hydra_targets[j]->redo_pass[i], out);
      }
    if (hydra_targets[j]->skipcnt >= hydra_brains.countlogin)
      hydra_targets[j]->skipcnt = 0;
    if (hydra_targets[j]->skipcnt > 0)
      for (i = 0; i < hydra_targets[j]->skipcnt; i++) {
        sck = fgets(out, sizeof(out), f);
        if (out[0] != 0 && out[strlen(out) - 1] == '\n')
          out[strlen(out) - 1] = 0;
        hydra_targets[j]->skiplogin[i] = malloc(strlen(out) + 1);
        strcpy(hydra_targets[j]->skiplogin[i], out);
      }
    hydra_targets[j]->fail_count = 0;
    hydra_targets[j]->use_count = 0;
    hydra_targets[j]->failed = 0;
  }
  if (debug) printf("[DEBUG] reading restore file: Step 11 complete\n");
  hydra_heads = malloc((hydra_options.max_use + 2) * sizeof(int) + 8);
  for (j = 0; j < hydra_options.max_use; j++) {
    hydra_heads[j] = malloc(sizeof(hydra_head));
    fck = (int) fread(hydra_heads[j], sizeof(hydra_head), 1, f);
    hydra_heads[j]->sp[0] = -1;
    hydra_heads[j]->sp[1] = -1;
    sck = fgets(out, sizeof(out), f);
    if (hydra_heads[j]->redo) {
      if (out[0] != 0 && out[strlen(out) - 1] == '\n')
        out[strlen(out) - 1] = 0;
      hydra_heads[j]->current_login_ptr = malloc(strlen(out) + 1);
      strcpy(hydra_heads[j]->current_login_ptr, out);
    }
    sck = fgets(out, sizeof(out), f);
    if (hydra_heads[j]->redo) {
      if (out[0] != 0 && out[strlen(out) - 1] == '\n')
        out[strlen(out) - 1] = 0;
if (debug) printf("[DEBUG] TEMP head %d: out[0] == %d, hydra_heads[j]->current_login_ptr[0] == %d\n", j, out[0], hydra_heads[j]->current_login_ptr[0]);
      if (out[0] != 0 || hydra_heads[j]->current_login_ptr[0] != 0) {
        hydra_heads[j]->current_pass_ptr = malloc(strlen(out) + 1);
        strcpy(hydra_heads[j]->current_pass_ptr, out);
        if (debug)
          printf("[DEBUG] redo: %d %s/%s\n", j, hydra_heads[j]->current_login_ptr, hydra_heads[j]->current_pass_ptr);
      } else {
        hydra_heads[j]->redo = 0;
        free(hydra_heads[j]->current_login_ptr);
        hydra_heads[j]->current_login_ptr = hydra_heads[j]->current_pass_ptr = empty_login;
      }
    } else {
      hydra_heads[j]->current_login_ptr = hydra_heads[j]->current_pass_ptr = empty_login;
    }
  }
  if (debug) printf("[DEBUG] reading restore file: Step 12 complete\n");
  sck = fgets(out, sizeof(out), f);
  if (out[0] != 0 && out[strlen(out) - 1] == '\n')
    out[strlen(out) - 1] = 0;
  if (strcmp(out, PROGRAM) != 0) {
    fprintf(stderr, "[ERROR] invalid restore file (end)\n");
    exit(-1);
  }
  fclose(f);
  hydra_debug(0, "hydra_restore_read");
}

void killed_childs(int signo) {
  int pid, i;

  killed++;
  pid = wait3(NULL, WNOHANG, NULL);
  for (i = 0; i < hydra_options.max_use; i++) {
    if (pid == hydra_heads[i]->pid) {
      hydra_heads[i]->pid = -1;
      hydra_kill_head(i, 1, 0);
      return;
    }
  }
}

void killed_childs_report(int signo) {
  if (debug)
    printf("[DEBUG] children crashed! (%d)\n", child_head_no);
  fck = write(child_socket, "E", 1);
  _exit(-1);
}

void kill_children(int signo) {
  int i;

  if (verbose)
    fprintf(stderr, "[ERROR] Received signal %d, going down ...\n", signo);
  if (process_restore == 1)
    hydra_restore_write(1);
  if (hydra_heads != NULL) {
    for (i = 0; i < hydra_options.max_use; i++)
      if (hydra_heads[i] != NULL && hydra_heads[i]->pid > 0)
        kill(hydra_heads[i]->pid, SIGTERM);
    for (i = 0; i < hydra_options.max_use; i++)
      if (hydra_heads[i] != NULL && hydra_heads[i]->pid > 0)
        kill(hydra_heads[i]->pid, SIGKILL);
  }
  exit(0);
}

unsigned long int countlines(FILE * fp, int colonmode) {
  size_t lines = 0;
  char *buf = malloc(MAXLINESIZE);
  int only_one_empty_line = 0;
  struct stat st;

  while (!feof(fp)) {
    if (fgets(buf, MAXLINESIZE, fp) != NULL) {
      if (buf[0] != 0) {
        if (buf[0] == '\r' || buf[0] == '\n') {
          if (only_one_empty_line == 0) {
            only_one_empty_line = 1;
            lines++;
          }
        } else {
          lines++;
        }
      }
    }
  }
  rewind(fp);
  free(buf);
  (void) fstat(fileno(fp), &st);
  size_of_data = st.st_size + 1;
  return lines;
}

void fill_mem(char *ptr, FILE * fp, int colonmode) {
  char tmp[MAXBUF + 4] = "", *ptr2;
  unsigned int len;
  int only_one_empty_line = 0;

  while (!feof(fp)) {
    if (fgets(tmp, MAXLINESIZE, fp) != NULL) {
      if (tmp[0] != 0) {
        if (tmp[strlen(tmp) - 1] == '\n')
          tmp[strlen(tmp) - 1] = '\0';
        if (tmp[0] != 0 && tmp[strlen(tmp) - 1] == '\r')
          tmp[strlen(tmp) - 1] = '\0';
        if ((len = strlen(tmp)) > 0 || (only_one_empty_line == 0 && colonmode == 0)) {
          if (len == 0 && colonmode == 0) {
            only_one_empty_line = 1;
            len = 1;
            tmp[len] = 0;
          }
          if (colonmode) {
            if ((ptr2 = index(tmp, ':')) == NULL) {
              fprintf(stderr, "[ERROR] invalid line in colon file (-C), missing colon in line: %s\n", tmp);
              exit(-1);
            } else {
//              if (tmp[0] == ':') {
//                *ptr = 0;
//                ptr++;
//              }
//              if (tmp[len - 1] == ':' && len > 1) {
//                len++;
//                tmp[len - 1] = 0;
//              }
              *ptr2 = 0;
            }
          }
          memcpy(ptr, tmp, len);
          ptr += len;
          *ptr = '\0';
          ptr++;
        }
      }
    }
  }
  fclose(fp);
}

char *hydra_build_time() {
  static char datetime[24];
  struct tm *the_time;
  time_t epoch;

  time(&epoch);
  the_time = localtime(&epoch);
  strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", the_time);
  return (char *) &datetime;
}

void hydra_service_init(int target_no) {
  int x = 99;

#ifdef LIBAFP
  if (strcmp(hydra_options.service, "afp") == 0)
    x = service_afp_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
  if (strcmp(hydra_options.service, "asterisk") == 0)
    x = service_asterisk_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "cisco-enable") == 0)
    x = service_cisco_enable_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "cvs") == 0)
    x = service_cvs_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "cisco") == 0)
    x = service_cisco_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#ifdef LIBFIREBIRD
  if (strcmp(hydra_options.service, "firebird") == 0)
    x = service_firebird_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
  if (strcmp(hydra_options.service, "ftp") == 0 || strcmp(hydra_options.service, "ftps") == 0)
    x = service_ftp_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "redis") == 0 || strcmp(hydra_options.service, "redis") == 0)
    x = service_redis_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "http-get") == 0 || strcmp(hydra_options.service, "http-head") == 0)
    x = service_http_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "http-form") == 0 || strcmp(hydra_options.service, "http-get-form") == 0 || strcmp(hydra_options.service, "http-post-form") == 0)
    x = service_http_form_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "http-proxy") == 0)
    x = service_http_proxy_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "http-proxy-urlenum") == 0)
    x = service_http_proxy_urlenum_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "icq") == 0)
    x = service_icq_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "imap") == 0)
    x = service_imap_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "irc") == 0)
    x = service_irc_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strncmp(hydra_options.service, "ldap", 4) == 0)
    x = service_ldap_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#ifdef LIBOPENSSL
  if (strcmp(hydra_options.service, "sip") == 0)
    x = service_sip_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "smb") == 0 || strcmp(hydra_options.service, "smbnt") == 0)
    x = service_smb_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "oracle-listener") == 0)
    x = service_oracle_listener_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "oracle-sid") == 0)
    x = service_oracle_sid_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "rdp") == 0)
    x = service_rdp_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
  if (strcmp(hydra_options.service, "mssql") == 0)
    x = service_mssql_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#ifdef HAVE_MATH_H
  if (strcmp(hydra_options.service, "mysql") == 0)
    x = service_mysql_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
#ifdef LIBNCP
  if (strcmp(hydra_options.service, "ncp") == 0)
    x = service_ncp_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
  if (strcmp(hydra_options.service, "nntp") == 0)
    x = service_nntp_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#ifdef LIBORACLE
  if (strcmp(hydra_options.service, "oracle") == 0)
    x = service_oracle_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
  if (strcmp(hydra_options.service, "pcanywhere") == 0)
    x = service_pcanywhere_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "pcnfs") == 0)
    x = service_pcnfs_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "pop3") == 0)
    x = service_pop3_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#ifdef LIBPOSTGRES
  if (strcmp(hydra_options.service, "postgres") == 0)
    x = service_postgres_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
  if (strcmp(hydra_options.service, "rexec") == 0)
    x = service_rexec_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "rlogin") == 0)
    x = service_rlogin_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "rsh") == 0)
    x = service_rsh_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#ifdef LIBSAPR3
  if (strcmp(hydra_options.service, "sapr3") == 0)
    x = service_sapr3_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
  if (strcmp(hydra_options.service, "smtp") == 0)
    x = service_smtp_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "smtp-enum") == 0)
    x = service_smtp_enum_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "snmp") == 0)
    x = service_snmp_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "socks5") == 0)
    x = service_socks5_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#ifdef LIBSSH
  if (strcmp(hydra_options.service, "ssh") == 0)
    x = service_ssh_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "sshkey") == 0)
    x = service_sshkey_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
#ifdef LIBSVN
  if (strcmp(hydra_options.service, "svn") == 0)
    x = service_svn_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
  if (strcmp(hydra_options.service, "teamspeak") == 0)
    x = service_teamspeak_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "telnet") == 0)
    x = service_telnet_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "vmauthd") == 0)
    x = service_vmauthd_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "vnc") == 0)
    x = service_vnc_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "xmpp") == 0)
    x = service_xmpp_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
  if (strcmp(hydra_options.service, "s7-300") == 0)
    x = service_s7_300_init(hydra_targets[target_no]->ip, -1, options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
// ADD NEW SERVICES HERE

  if (x != 0 && x != 99) {
    if (x > 0 && x < 4)
      hydra_targets[target_no]->done = x;
    else
      hydra_targets[target_no]->done = 2;
    hydra_brains.finished++;
    if (hydra_brains.targets == 1)
      exit(-1);
  }
}


int hydra_spawn_head(int head_no, int target_no) {
  int i;

  if (head_no < 0 || head_no >= hydra_options.max_use || target_no < 0 || target_no >= hydra_brains.targets) {
    if (verbose > 1 || debug)
      printf("[DEBUG-ERROR] spawn_head: head_no %d, target_no %d\n", head_no, target_no);
    return -1;
  }

  if (hydra_heads[head_no]->active < 0) {
    printf("[DEBUG-ERROR] child %d should not be respawned!\n", head_no);
    return -1;
  }

  if (socketpair(PF_UNIX, SOCK_STREAM, 0, hydra_heads[head_no]->sp) == 0) {
    child_head_no = head_no;
    if ((hydra_heads[head_no]->pid = fork()) == 0) {    // THIS IS THE CHILD 
      // set new signals for child 
      process_restore = 0;
      child_socket = hydra_heads[head_no]->sp[1];
      signal(SIGCHLD, killed_childs);
      signal(SIGTERM, exit);
#ifdef SIGBUS
      signal(SIGBUS, exit);
#endif
      signal(SIGSEGV, killed_childs_report);
      signal(SIGHUP, exit);
      signal(SIGINT, exit);
      signal(SIGPIPE, exit);
      // free structures to make memory available 
      cmdlinetarget = hydra_targets[target_no]->target;
      for (i = 0; i < hydra_options.max_use; i++)
        if (i != head_no)
          free(hydra_heads[i]);
      for (i = 0; i < hydra_brains.targets; i++)
        if (i != target_no)
          free(hydra_targets[i]);
      if (hydra_options.loginfile != NULL)
        free(login_ptr);
      if (hydra_options.passfile != NULL)
        free(pass_ptr);
      if (hydra_options.colonfile != NULL && hydra_options.colonfile != empty_login)
        free(csv_ptr);
//    we must keep servers_ptr for cmdlinetarget to work
      if (debug)
        printf("[DEBUG] head_no %d has pid %d\n", head_no, getpid());

      // now call crack module 
      if (strcmp(hydra_options.service, "asterisk") == 0)
        service_asterisk(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "telnet") == 0)
        service_telnet(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "ftp") == 0)
        service_ftp(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "ftps") == 0)
        service_ftps(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "redis") == 0)
        service_redis(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "pop3") == 0)
        service_pop3(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "imap") == 0)
        service_imap(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "vmauthd") == 0)
        service_vmauthd(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "ldap2") == 0)
        service_ldap2(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "ldap3") == 0)
        service_ldap3(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "http-head") == 0)
        service_http_head(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "ldap3-crammd5") == 0)
        service_ldap3_cram_md5(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "ldap3-digestmd5") == 0)
        service_ldap3_digest_md5(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "http-get") == 0)
        service_http_get(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "http-get-form") == 0)
        service_http_get_form(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "http-post-form") == 0)
        service_http_post_form(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "http-proxy") == 0)
        service_http_proxy(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "http-proxy-urlenum") == 0)
        service_http_proxy_urlenum(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "cisco") == 0)
        service_cisco(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "cisco-enable") == 0)
        service_cisco_enable(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "socks5") == 0)
        service_socks5(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "vnc") == 0)
        service_vnc(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "rexec") == 0)
        service_rexec(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "rlogin") == 0)
        service_rlogin(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "rsh") == 0)
        service_rsh(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "nntp") == 0)
        service_nntp(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "icq") == 0)
        service_icq(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "pcnfs") == 0)
        service_pcnfs(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#ifdef HAVE_MATH_H
      if (strcmp(hydra_options.service, "mysql") == 0)
        service_mysql(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
      if (strcmp(hydra_options.service, "mssql") == 0)
        service_mssql(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#ifdef LIBOPENSSL
      if (strcmp(hydra_options.service, "oracle-listener") == 0)
        service_oracle_listener(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "oracle-sid") == 0)
        service_oracle_sid(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
#ifdef LIBORACLE
      if (strcmp(hydra_options.service, "oracle") == 0)
        service_oracle(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
#ifdef LIBPOSTGRES
      if (strcmp(hydra_options.service, "postgres") == 0)
        service_postgres(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
#ifdef LIBFIREBIRD
      if (strcmp(hydra_options.service, "firebird") == 0)
        service_firebird(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
#ifdef LIBAFP
      if (strcmp(hydra_options.service, "afp") == 0)
        service_afp(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
#ifdef LIBNCP
      if (strcmp(hydra_options.service, "ncp") == 0)
        service_ncp(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
      if (strcmp(hydra_options.service, "pcanywhere") == 0)
        service_pcanywhere(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "cvs") == 0)
        service_cvs(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#ifdef LIBSVN
      if (strcmp(hydra_options.service, "svn") == 0)
        service_svn(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
      if (strcmp(hydra_options.service, "snmp") == 0)
        service_snmp(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#ifdef LIBOPENSSL
      if ((strcmp(hydra_options.service, "smb") == 0) || (strcmp(hydra_options.service, "smbnt") == 0))
        service_smb(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
#ifdef LIBSAPR3
      if (strcmp(hydra_options.service, "sapr3") == 0)
        service_sapr3(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
#ifdef LIBSSH
      if (strcmp(hydra_options.service, "ssh") == 0)
        service_ssh(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "sshkey") == 0)
        service_sshkey(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
      if (strcmp(hydra_options.service, "smtp") == 0)
        service_smtp(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "smtp-enum") == 0)
        service_smtp_enum(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "teamspeak") == 0)
        service_teamspeak(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#ifdef LIBOPENSSL
      if (strcmp(hydra_options.service, "sip") == 0)
        service_sip(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
      if (strcmp(hydra_options.service, "xmpp") == 0)
        service_xmpp(hydra_targets[target_no]->target, hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp,
                     hydra_targets[target_no]->port);
      if (strcmp(hydra_options.service, "irc") == 0)
        service_irc(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#ifdef LIBOPENSSL
      if (strcmp(hydra_options.service, "rdp") == 0)
        service_rdp(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
#endif
      if (strcmp(hydra_options.service, "s7-300") == 0)
        service_s7_300(hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port);
// ADD NEW SERVICES HERE 

      // just in case a module returns (which it shouldnt) we let it exit here 
      exit(-1);
    } else {
      child_head_no = -1;
      if (hydra_heads[head_no]->pid > 0) {
        fck = write(hydra_heads[head_no]->sp[1], "n", 1);       // yes, a small "n" - this way we can distinguish later if the client successfully tested a pair and is requesting a new one or the mother did that 
        (void) fcntl(hydra_heads[head_no]->sp[0], F_SETFL, O_NONBLOCK);
        if (hydra_heads[head_no]->redo != 1)
          hydra_heads[head_no]->target_no = target_no;
        hydra_heads[head_no]->active = 1;
        hydra_targets[hydra_heads[head_no]->target_no]->use_count++;
        hydra_brains.active++;
        hydra_heads[head_no]->last_seen = time(NULL);
        if (debug)
          printf("[DEBUG] child %d spawned for target %d with pid %d\n", head_no, hydra_heads[head_no]->target_no, hydra_heads[head_no]->pid);
      } else {
        perror("[ERROR] Fork for children failed");
        hydra_heads[head_no]->sp[0] = -1;
        hydra_heads[head_no]->active = 0;
        return -1;
      }
    }
  } else {
    perror("[ERROR] socketpair creation failed");
    hydra_heads[head_no]->sp[0] = -1;
    hydra_heads[head_no]->active = 0;
    return -1;
  }
  return 0;
}

int hydra_lookup_port(char *service) {
  int i = 0, port = -2;

  hydra_portlist hydra_portlists[] = {
    {"ftp", PORT_FTP, PORT_FTP_SSL},
    {"ftps", PORT_FTP, PORT_FTP_SSL},
    {"http-head", PORT_HTTP, PORT_HTTP_SSL},
    {"http-get", PORT_HTTP, PORT_HTTP_SSL},
    {"http-get-form", PORT_HTTP, PORT_HTTP_SSL},
    {"http-post-form", PORT_HTTP, PORT_HTTP_SSL},
    {"https-get-form", PORT_HTTP, PORT_HTTP_SSL},
    {"https-post-form", PORT_HTTP, PORT_HTTP_SSL},
    {"https-head", PORT_HTTP, PORT_HTTP_SSL},
    {"https-get", PORT_HTTP, PORT_HTTP_SSL},
    {"http-proxy", PORT_HTTP_PROXY, PORT_HTTP_PROXY_SSL},
    {"http-proxy-urlenum", PORT_HTTP_PROXY, PORT_HTTP_PROXY_SSL},
    {"icq", PORT_ICQ, PORT_ICQ_SSL},
    {"imap", PORT_IMAP, PORT_IMAP_SSL},
    {"ldap2", PORT_LDAP, PORT_LDAP_SSL},
    {"ldap3", PORT_LDAP, PORT_LDAP_SSL},
    {"ldap3-crammd5", PORT_LDAP, PORT_LDAP_SSL},
    {"ldap3-digestmd5", PORT_LDAP, PORT_LDAP_SSL},
    {"oracle-listener", PORT_ORACLE, PORT_ORACLE_SSL},
    {"oracle-sid", PORT_ORACLE, PORT_ORACLE_SSL},
    {"oracle", PORT_ORACLE, PORT_ORACLE_SSL},
    {"mssql", PORT_MSSQL, PORT_MSSQL_SSL},
    {"mysql", PORT_MYSQL, PORT_MYSQL_SSL},
    {"postgres", PORT_POSTGRES, PORT_POSTGRES_SSL},
    {"pcanywhere", PORT_PCANYWHERE, PORT_PCANYWHERE_SSL},
    {"nntp", PORT_NNTP, PORT_NNTP_SSL},
    {"pcnfs", PORT_PCNFS, PORT_PCNFS_SSL},
    {"pop3", PORT_POP3, PORT_POP3_SSL},
    {"redis", PORT_REDIS, PORT_REDIS_SSL},
    {"rexec", PORT_REXEC, PORT_REXEC_SSL},
    {"rlogin", PORT_RLOGIN, PORT_RLOGIN_SSL},
    {"rsh", PORT_RSH, PORT_RSH_SSL},
    {"sapr3", PORT_SAPR3, PORT_SAPR3_SSL},
    {"smb", PORT_SMBNT, PORT_SMBNT_SSL},
    {"smbnt", PORT_SMBNT, PORT_SMBNT_SSL},
    {"socks5", PORT_SOCKS5, PORT_SOCKS5_SSL},
    {"ssh", PORT_SSH, PORT_SSH_SSL},
    {"sshkey", PORT_SSH, PORT_SSH_SSL},
    {"telnet", PORT_TELNET, PORT_TELNET_SSL},
    {"cisco", PORT_TELNET, PORT_TELNET_SSL},
    {"cisco-enable", PORT_TELNET, PORT_TELNET_SSL},
    {"vnc", PORT_VNC, PORT_VNC_SSL},
    {"snmp", PORT_SNMP, PORT_SNMP_SSL},
    {"cvs", PORT_CVS, PORT_CVS_SSL},
    {"svn", PORT_SVN, PORT_SVN_SSL},
    {"firebird", PORT_FIREBIRD, PORT_FIREBIRD_SSL},
    {"afp", PORT_AFP, PORT_AFP_SSL},
    {"ncp", PORT_NCP, PORT_NCP_SSL},
    {"smtp", PORT_SMTP, PORT_SMTP_SSL},
    {"smtp-enum", PORT_SMTP, PORT_SMTP_SSL},
    {"teamspeak", PORT_TEAMSPEAK, PORT_TEAMSPEAK_SSL},
    {"sip", PORT_SIP, PORT_SIP_SSL},
    {"vmauthd", PORT_VMAUTHD, PORT_VMAUTHD_SSL},
    {"xmpp", PORT_XMPP, PORT_XMPP_SSL},
    {"irc", PORT_IRC, PORT_IRC_SSL},
    {"rdp", PORT_RDP, PORT_RDP_SSL},
    {"asterisk", PORT_ASTERISK, PORT_ASTERISK_SSL},
    {"s7-300", PORT_S7_300, PORT_S7_300_SSL},
// ADD NEW SERVICES HERE - add new port numbers to hydra.h 
    {"", PORT_NOPORT, PORT_NOPORT}
  };

  while (strlen(hydra_portlists[i].name) > 0 && port == -2) {
    if (strcmp(service, hydra_portlists[i].name) == 0) {
      if (hydra_options.ssl)
        port = hydra_portlists[i].port_ssl;
      else
        port = hydra_portlists[i].port;
    }
    i++;
  }
  if (port < 1)
    return -1;
  else
    return port;
}

// killit = 1 : kill(pid); fail = 1 : redo, fail = 2/3 : disable
void hydra_kill_head(int head_no, int killit, int fail) {
  if (debug) printf("[DEBUG] head_no %d, kill %d, fail %d\n", head_no, killit, fail);
  if (head_no < 0)
    return;
  if (hydra_heads[head_no]->active > 0) {
    close(hydra_heads[head_no]->sp[0]);
    close(hydra_heads[head_no]->sp[1]);
  }
  if (killit) {
    if (hydra_heads[head_no]->pid > 0)
      kill(hydra_heads[head_no]->pid, SIGTERM);
    hydra_brains.active--;
  }
  if (hydra_heads[head_no]->active > 0) {
    hydra_heads[head_no]->active = 0;
    hydra_targets[hydra_heads[head_no]->target_no]->use_count--;
  }
  if (fail == 1) {
    if (hydra_options.cidr != 1)
      hydra_heads[head_no]->redo = 1;
  } else if (fail == 2) {
    if (hydra_options.cidr != 1)
      hydra_heads[head_no]->active = -1;
    if (hydra_heads[head_no]->target_no >= 0)
      hydra_targets[hydra_heads[head_no]->target_no]->failed++;
  } else if (fail == 3) {
    hydra_heads[head_no]->active = -1;
    if (hydra_heads[head_no]->target_no >= 0)
      hydra_targets[hydra_heads[head_no]->target_no]->failed++;
  }
  if (hydra_heads[head_no]->pid > 0 && killit)
    kill(hydra_heads[head_no]->pid, SIGKILL);
  hydra_heads[head_no]->pid = -1;
  if (fail < 1 && hydra_heads[head_no]->target_no >= 0 && hydra_options.bfg && hydra_targets[hydra_heads[head_no]->target_no]->pass_state == 3
      && strlen(hydra_heads[head_no]->current_pass_ptr) > 0 && hydra_heads[head_no]->current_pass_ptr != hydra_heads[head_no]->current_login_ptr) {
    free(hydra_heads[head_no]->current_pass_ptr);
    hydra_heads[head_no]->current_pass_ptr = empty_login;
//    hydra_bfg_remove(head_no);
//    hydra_targets[hydra_heads[head_no]->target_no]->bfg_ptr[head_no] = NULL;
  }
  (void) wait3(NULL, WNOHANG, NULL);
}

void hydra_increase_fail_count(int target_no, int head_no) {
  int i, k;

  if (target_no < 0)
    return;

  hydra_targets[target_no]->fail_count++;
  if (debug)
    printf("[DEBUG] hydra_increase_fail_count: %d >= %d => disable\n", hydra_targets[target_no]->fail_count,
           MAXFAIL + (hydra_options.tasks <= 4 && hydra_targets[target_no]->ok ? 6 - hydra_options.tasks : 1) + (hydra_options.tasks - hydra_targets[target_no]->failed < 5
                                                                                                                 && hydra_targets[target_no]->ok ? 6 - (hydra_options.tasks -
                                                                                                                                                        hydra_targets
                                                                                                                                                        [target_no]->failed) : 1)
           + (hydra_targets[target_no]->ok ? 2 : -2));
  if (hydra_targets[target_no]->fail_count >=
      MAXFAIL + (hydra_options.tasks <= 4 && hydra_targets[target_no]->ok ? 6 - hydra_options.tasks : 1) + (hydra_options.tasks - hydra_targets[target_no]->failed < 5
                                                                                                            && hydra_targets[target_no]->ok ? 6 - (hydra_options.tasks -
                                                                                                                                                   hydra_targets
                                                                                                                                                   [target_no]->failed) : 1) +
      (hydra_targets[target_no]->ok ? 2 : -2)
    ) {
    k = 0;
    for (i = 0; i < hydra_options.max_use; i++)
      if (hydra_heads[i]->active >= 0 && hydra_heads[i]->target_no == target_no)
        k++;
    if (k <= 1) {
      // we need to put this in a list, otherwise we fail one login+pw test
      if (hydra_targets[target_no]->done == 0
          && hydra_targets[target_no]->redo <= hydra_options.max_use * 2
          && ((hydra_heads[head_no]->current_login_ptr != empty_login && hydra_heads[head_no]->current_pass_ptr != empty_login)
              || (hydra_heads[head_no]->current_login_ptr != NULL && hydra_heads[head_no]->current_pass_ptr != NULL))) {
        hydra_targets[target_no]->redo_login[hydra_targets[target_no]->redo] = hydra_heads[head_no]->current_login_ptr;
        hydra_targets[target_no]->redo_pass[hydra_targets[target_no]->redo] = hydra_heads[head_no]->current_pass_ptr;
        hydra_targets[target_no]->redo++;
        if (debug)
          printf("[DEBUG] - will be retried at the end: ip %s - login %s - pass %s - child %d\n", hydra_targets[target_no]->target,
                 hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, head_no);
        hydra_heads[head_no]->current_login_ptr = empty_login;
        hydra_heads[head_no]->current_pass_ptr = empty_login;
      }
      if (hydra_targets[target_no]->fail_count >= MAXFAIL + hydra_options.tasks * hydra_targets[target_no]->ok) {
        if (hydra_targets[target_no]->done == 0 && hydra_options.max_use == hydra_targets[target_no]->failed) {
          if (hydra_targets[target_no]->ok == 1)
            hydra_targets[target_no]->done = 2; // mark target as done by errors
          else
            hydra_targets[target_no]->done = 3; // mark target as done by unable to connect
          hydra_brains.finished++;
          fprintf(stderr, "[ERROR] Too many connect errors to target, disabling %s://%s%s%s:%d\n", hydra_options.service, hydra_targets[target_no]->ip[0] == 16
                  && index(hydra_targets[target_no]->target, ':') != NULL ? "[" : "", hydra_targets[target_no]->target, hydra_targets[target_no]->ip[0] == 16
                  && index(hydra_targets[target_no]->target, ':') != NULL ? "]" : "", hydra_targets[target_no]->port);
        }
        if (hydra_brains.targets > hydra_brains.finished)
          hydra_kill_head(head_no, 1, 0);
        else
          hydra_kill_head(head_no, 1, 2);
      }                         // we keep the last one alive as long as it make sense
    } else {
      // we need to put this in a list, otherwise we fail one login+pw test
      if (hydra_targets[target_no]->done == 0
          && hydra_targets[target_no]->redo <= hydra_options.max_use * 2
          && ((hydra_heads[head_no]->current_login_ptr != empty_login && hydra_heads[head_no]->current_pass_ptr != empty_login)
              || (hydra_heads[head_no]->current_login_ptr != NULL && hydra_heads[head_no]->current_pass_ptr != NULL))) {
        hydra_targets[target_no]->redo_login[hydra_targets[target_no]->redo] = hydra_heads[head_no]->current_login_ptr;
        hydra_targets[target_no]->redo_pass[hydra_targets[target_no]->redo] = hydra_heads[head_no]->current_pass_ptr;
        hydra_targets[target_no]->redo++;
        if (debug)
          printf("[DEBUG] - will be retried at the end: ip %s - login %s - pass %s - child %d\n", hydra_targets[target_no]->target,
                 hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, head_no);
        hydra_heads[head_no]->current_login_ptr = empty_login;
        hydra_heads[head_no]->current_pass_ptr = empty_login;
      }
      hydra_targets[target_no]->fail_count--;
      if (k < 5 && hydra_targets[target_no]->ok)
        hydra_targets[target_no]->fail_count--;
      if (k == 2 && hydra_targets[target_no]->ok)
        hydra_targets[target_no]->fail_count--;
      if (hydra_brains.targets > hydra_brains.finished)
        hydra_kill_head(head_no, 1, 0);
      else {
        hydra_kill_head(head_no, 1, 2);
        if (verbose)
          printf("[VERBOSE] Disabled child %d because of too many errors\n", head_no);
      }
    }
  } else {
    hydra_kill_head(head_no, 1, 1);
    if (verbose)
      printf("[VERBOSE] Retrying connection for child %d\n", head_no);
  }
}

char *hydra_reverse_login(int head_no, char *login) {
  int i, j = strlen(login);

  if (j > 248)
    j = 248;
  else if (j == 0)
    return empty_login;
  for (i = 0; i < j; i++)
    hydra_heads[head_no]->reverse[i] = login[j - (i + 1)];
  hydra_heads[head_no]->reverse[j] = 0;

  return hydra_heads[head_no]->reverse;
}

int hydra_send_next_pair(int target_no, int head_no) {
  // variables moved to save stack
  snpdone = 0;
  snp_is_redo = 0;
  snpdont = 0;
  loop_cnt++;
  if (hydra_heads[head_no]->redo && hydra_heads[head_no]->current_login_ptr != NULL && hydra_heads[head_no]->current_pass_ptr != NULL) {
    hydra_heads[head_no]->redo = 0;
    snp_is_redo = 1;
    snpdone = 1;
  } else {
    if (hydra_targets[target_no]->sent >= hydra_brains.todo + hydra_targets[target_no]->redo) {
      if (hydra_targets[target_no]->done == 0) {
        hydra_targets[target_no]->done = 1;
        hydra_brains.finished++;
        if (verbose)
          printf("[STATUS] attack finished for %s (waiting for children to complete tests)\n", hydra_targets[target_no]->target);
      }
      return -1;
    }
  }

  if (debug)
    printf
      ("[DEBUG] send_next_pair_init target %d, head %d, redo %d, redo_state %d, pass_state %d. loop_mode %d, curlogin %s, curpass %s, tlogin %s, tpass %s, logincnt %lu/%lu, passcnt %lu/%lu, loop_cnt %d\n",
       target_no, head_no, hydra_heads[head_no]->redo, hydra_targets[target_no]->redo_state, hydra_targets[target_no]->pass_state, hydra_options.loop_mode,
       hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, hydra_targets[target_no]->login_ptr, hydra_targets[target_no]->pass_ptr,
       hydra_targets[target_no]->login_no, hydra_brains.countlogin, hydra_targets[target_no]->pass_no, hydra_brains.countpass, loop_cnt);

  if (loop_cnt > (hydra_brains.countlogin * 2) + 1 && loop_cnt > (hydra_brains.countpass * 2) + 1) {
    if (debug)
      printf("[DEBUG] too many loops in send_next_pair, returning -1 (loop_cnt %d, sent %ld, todo %ld)\n", loop_cnt, hydra_targets[target_no]->sent, hydra_brains.todo);
    return -1;
  }

  if (hydra_heads[head_no]->redo && hydra_heads[head_no]->current_login_ptr != NULL && hydra_heads[head_no]->current_pass_ptr != NULL) {
    hydra_heads[head_no]->redo = 0;
    snp_is_redo = 1;
    snpdone = 1;
  } else {
    if (debug && (hydra_heads[head_no]->current_login_ptr != NULL || hydra_heads[head_no]->current_pass_ptr != NULL))
      printf("[COMPLETED] target %s - login \"%s\" - pass \"%s\" - child %d - %lu of %lu\n",
             hydra_targets[target_no]->target, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, head_no,
             hydra_targets[target_no]->sent, hydra_brains.todo);
    hydra_heads[head_no]->redo = 0;
    if (hydra_targets[target_no]->redo_state > 0) {
      if (hydra_targets[target_no]->redo_state + 1 <= hydra_targets[target_no]->redo) {
        hydra_heads[head_no]->current_pass_ptr = hydra_targets[target_no]->redo_pass[hydra_targets[target_no]->redo_state - 1];
        hydra_heads[head_no]->current_login_ptr = hydra_targets[target_no]->redo_login[hydra_targets[target_no]->redo_state - 1];
        hydra_targets[target_no]->redo_state++;
        snpdone = 1;
      }                         // no else, that way a later lost pair is still added and done
    } else {                    // normale state, no redo
      if (hydra_targets[target_no]->done) {
        loop_cnt = 0;
        return -1;              // head will be disabled by main while()
      }
      if (hydra_options.loop_mode == 0) {       // one user after another
        if (hydra_targets[target_no]->login_no < hydra_brains.countlogin) {
          // as we loop password in mode == 0 we set the current login first
          hydra_heads[head_no]->current_login_ptr = hydra_targets[target_no]->login_ptr;
          // then we do the extra options -e ns handling
          if (hydra_targets[target_no]->pass_state == 0 && snpdone == 0) {
            if (hydra_options.try_password_same_as_login) {
              hydra_heads[head_no]->current_pass_ptr = hydra_targets[target_no]->login_ptr;
              snpdone = 1;
              hydra_targets[target_no]->pass_no++;
            }
            hydra_targets[target_no]->pass_state++;
          }
          if (hydra_targets[target_no]->pass_state == 1 && snpdone == 0) {
            // small check that there is a login name (could also be emtpy) and if we already tried empty password it would be a double
            if (hydra_options.try_null_password) {
              if (hydra_options.try_password_same_as_login == 0 || (hydra_targets[target_no]->login_ptr != NULL && strlen(hydra_targets[target_no]->login_ptr) > 0)) {
                hydra_heads[head_no]->current_pass_ptr = empty_login;
                snpdone = 1;
              } else {
                hydra_brains.sent++;
                hydra_targets[target_no]->sent++;
              }
              hydra_targets[target_no]->pass_no++;
            }
            hydra_targets[target_no]->pass_state++;
          }
          if (hydra_targets[target_no]->pass_state == 2 && snpdone == 0) {
            // small check that there is a login name (could also be emtpy) and if we already tried empty password it would be a double
            if (hydra_options.try_password_reverse_login) {
              if ((hydra_options.try_password_same_as_login == 0
                   || strcmp(hydra_targets[target_no]->login_ptr, hydra_reverse_login(head_no, hydra_heads[head_no]->current_login_ptr)) != 0)
                  && (hydra_options.try_null_password == 0 || (hydra_targets[target_no]->login_ptr != NULL && strlen(hydra_targets[target_no]->login_ptr) > 0))) {
                hydra_heads[head_no]->current_pass_ptr = hydra_reverse_login(head_no, hydra_heads[head_no]->current_login_ptr);
                snpdone = 1;
              } else {
                hydra_brains.sent++;
                hydra_targets[target_no]->sent++;
              }
              hydra_targets[target_no]->pass_no++;
            }
            hydra_targets[target_no]->pass_state++;
          }
          // now we handle the -C -l/-L -p/-P data
          if (hydra_targets[target_no]->pass_state == 3 && snpdone == 0) {
            if ((hydra_options.mode & 64) == 64) {      // colon mode
              hydra_heads[head_no]->current_login_ptr = hydra_targets[target_no]->login_ptr;
              hydra_heads[head_no]->current_pass_ptr = hydra_targets[target_no]->pass_ptr;
              hydra_targets[target_no]->login_no++;
              snpdone = 1;
              hydra_targets[target_no]->login_ptr = hydra_targets[target_no]->pass_ptr;
              //hydra_targets[target_no]->login_ptr++;
              while (*hydra_targets[target_no]->login_ptr != 0)
                hydra_targets[target_no]->login_ptr++;
              hydra_targets[target_no]->login_ptr++;
              hydra_targets[target_no]->pass_ptr = hydra_targets[target_no]->login_ptr;
              //hydra_targets[target_no]->pass_ptr++;
              while (*hydra_targets[target_no]->pass_ptr != 0)
                hydra_targets[target_no]->pass_ptr++;
              hydra_targets[target_no]->pass_ptr++;
              if (strcmp(hydra_targets[target_no]->login_ptr, hydra_heads[head_no]->current_login_ptr) != 0)
                hydra_targets[target_no]->pass_state = 0;
              if ((hydra_options.try_password_same_as_login && strcmp(hydra_heads[head_no]->current_pass_ptr, hydra_heads[head_no]->current_login_ptr) == 0)
                  || (hydra_options.try_null_password && strlen(hydra_heads[head_no]->current_pass_ptr) == 0)
                  ||
                  (hydra_options.try_password_reverse_login
                   && strcmp(hydra_heads[head_no]->current_pass_ptr, hydra_reverse_login(head_no, hydra_heads[head_no]->current_login_ptr)) == 0)) {
                hydra_brains.sent++;
                hydra_targets[target_no]->sent++;
                if (debug)
                  printf("[DEBUG] double detected (-C)\n");
                return hydra_send_next_pair(target_no, head_no);        // little trick to keep the code small
              }
            } else {            // standard -l -L -p -P mode
              hydra_heads[head_no]->current_pass_ptr = hydra_targets[target_no]->pass_ptr;
              hydra_targets[target_no]->pass_no++;
              // double check
              if (hydra_targets[target_no]->pass_no >= hydra_brains.countpass) {
                // all passwords done, next user for next password
                hydra_targets[target_no]->login_ptr++;
                while (*hydra_targets[target_no]->login_ptr != 0)
                  hydra_targets[target_no]->login_ptr++;
                hydra_targets[target_no]->login_ptr++;
                hydra_targets[target_no]->pass_ptr = pass_ptr;
                hydra_targets[target_no]->login_no++;
                hydra_targets[target_no]->pass_no = 0;
                hydra_targets[target_no]->pass_state = 0;
                if (hydra_brains.countpass == hydra_options.try_password_reverse_login + hydra_options.try_null_password + hydra_options.try_password_same_as_login)
                  return hydra_send_next_pair(target_no, head_no);
              } else {
                hydra_targets[target_no]->pass_ptr++;
                while (*hydra_targets[target_no]->pass_ptr != 0)
                  hydra_targets[target_no]->pass_ptr++;
                hydra_targets[target_no]->pass_ptr++;
              }
              if ((hydra_options.try_password_same_as_login && strcmp(hydra_heads[head_no]->current_pass_ptr, hydra_heads[head_no]->current_login_ptr) == 0)
                  || (hydra_options.try_null_password && strlen(hydra_heads[head_no]->current_pass_ptr) == 0)
                  ||
                  (hydra_options.try_password_reverse_login
                   && strcmp(hydra_heads[head_no]->current_pass_ptr, hydra_reverse_login(head_no, hydra_heads[head_no]->current_login_ptr)) == 0)) {
                hydra_brains.sent++;
                hydra_targets[target_no]->sent++;
                if (debug)
                  printf("[DEBUG] double detected (-Pp)\n");
                return hydra_send_next_pair(target_no, head_no);        // little trick to keep the code small
              }
              snpdone = 1;
            }
          }
        }
      } else {                  // loop_mode == 1
        if (hydra_targets[target_no]->pass_no < hydra_brains.countpass) {
          hydra_heads[head_no]->current_login_ptr = hydra_targets[target_no]->login_ptr;
          if (hydra_targets[target_no]->pass_state == 0) {
            if ((hydra_options.mode & 4) == 4)
              hydra_heads[head_no]->current_pass_ptr = strdup(hydra_heads[head_no]->current_login_ptr);
            else
              hydra_heads[head_no]->current_pass_ptr = hydra_heads[head_no]->current_login_ptr;
          } else if (hydra_targets[target_no]->pass_state == 1) {
            if ((hydra_options.mode & 4) == 4)
              hydra_heads[head_no]->current_pass_ptr = strdup(empty_login);
            else
              hydra_heads[head_no]->current_pass_ptr = empty_login;
          } else if (hydra_targets[target_no]->pass_state == 2) {
            if ((hydra_options.mode & 4) == 4)
              hydra_heads[head_no]->current_pass_ptr = strdup(hydra_reverse_login(head_no, hydra_heads[head_no]->current_login_ptr));
            else
              hydra_heads[head_no]->current_pass_ptr = hydra_reverse_login(head_no, hydra_heads[head_no]->current_login_ptr);
          } else {
            if (hydra_options.bfg && hydra_targets[target_no]->pass_state == 3
                && hydra_heads[head_no]->current_pass_ptr != NULL &&
                strlen(hydra_heads[head_no]->current_pass_ptr) > 0 && hydra_heads[head_no]->current_pass_ptr != hydra_heads[head_no]->current_login_ptr)
              free(hydra_heads[head_no]->current_pass_ptr);
            hydra_heads[head_no]->current_pass_ptr = strdup(hydra_targets[target_no]->pass_ptr);
          }
          hydra_targets[target_no]->login_no++;
          snpdone = 1;

          if (hydra_targets[target_no]->login_no >= hydra_brains.countlogin) {
            if (hydra_targets[target_no]->pass_state < 3) {
              hydra_targets[target_no]->pass_state++;
              if (hydra_targets[target_no]->pass_state == 1 && hydra_options.try_null_password == 0)
                hydra_targets[target_no]->pass_state++;
              if (hydra_targets[target_no]->pass_state == 2 && hydra_options.try_password_reverse_login == 0)
                hydra_targets[target_no]->pass_state++;
              if (hydra_targets[target_no]->pass_state == 3)
                snpdont = 1;
              hydra_targets[target_no]->pass_no++;
            }

            if (hydra_targets[target_no]->pass_state == 3) {
              if (snpdont) {
                hydra_targets[target_no]->pass_ptr = pass_ptr;
              } else {
                if ((hydra_options.mode & 4) == 4) {    // bfg mode
#ifndef HAVE_MATH_H
                  sleep(1);
#else
                  hydra_targets[target_no]->pass_ptr = bf_next();
                  if (debug)
                    printf("[DEBUG] bfg new password for next child: %s\n", hydra_targets[target_no]->pass_ptr);
#endif
                } else {        // -p -P mode
                  hydra_targets[target_no]->pass_ptr++;
                  while (*hydra_targets[target_no]->pass_ptr != 0)
                    hydra_targets[target_no]->pass_ptr++;
                  hydra_targets[target_no]->pass_ptr++;
                }
                hydra_targets[target_no]->pass_no++;
              }
            }

            hydra_targets[target_no]->login_no = 0;
            hydra_targets[target_no]->login_ptr = login_ptr;
          } else if (hydra_targets[target_no]->login_no < hydra_brains.countlogin) {
            hydra_targets[target_no]->login_ptr++;
            while (*hydra_targets[target_no]->login_ptr != 0)
              hydra_targets[target_no]->login_ptr++;
            hydra_targets[target_no]->login_ptr++;
          }
          if (hydra_targets[target_no]->pass_state == 3 && snpdont == 0) {
            if ((hydra_options.try_null_password && strlen(hydra_heads[head_no]->current_pass_ptr) < 1)
                || (hydra_options.try_password_same_as_login && strcmp(hydra_heads[head_no]->current_pass_ptr, hydra_heads[head_no]->current_login_ptr) == 0)
                || (hydra_options.try_password_reverse_login && strcmp(hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr) == 0)) {
              hydra_brains.sent++;
              hydra_targets[target_no]->sent++;
              if (debug)
                printf("[DEBUG] double detected (1)\n");
              return hydra_send_next_pair(target_no, head_no);  // little trick to keep the code small
            }
          }
        }
      }
    }

    if (debug)
      printf("[DEBUG] send_next_pair_mid done %d, pass_state %d, clogin %s, cpass %s, tlogin %s, tpass %s, redo %d\n",
             snpdone, hydra_targets[target_no]->pass_state, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, hydra_targets[target_no]->login_ptr,
             hydra_targets[target_no]->pass_ptr, hydra_targets[target_no]->redo);

    // no pair? then we go for redo state
    if (!snpdone && hydra_targets[target_no]->redo_state == 0 && hydra_targets[target_no]->redo > 0) {
      if (debug)
        printf("[DEBUG] Entering redo_state\n");
      hydra_targets[target_no]->redo_state++;
      return hydra_send_next_pair(target_no, head_no);  // little trick to keep the code small
    }
  }

  if (!snpdone || hydra_targets[target_no]->skipcnt >= hydra_brains.countlogin) {
    fck = write(hydra_heads[head_no]->sp[0], HYDRA_EXIT, sizeof(HYDRA_EXIT));
    if (hydra_targets[target_no]->use_count <= 1) {
      if (hydra_targets[target_no]->done == 0) {
        hydra_targets[target_no]->done = 1;
        hydra_brains.finished++;
        printf("[STATUS] attack finished for %s (waiting for children to finish) ...\n", hydra_targets[target_no]->target);
      }
    }
    if (hydra_brains.targets > hydra_brains.finished)
      hydra_kill_head(head_no, 1, 0); // otherwise done in main while loop
  } else {
    if (hydra_targets[target_no]->skipcnt > 0) {
      snpj = 0;
      for (snpi = 0; snpi < hydra_targets[target_no]->skipcnt && snpj == 0; snpi++)
        if (strcmp(hydra_heads[head_no]->current_login_ptr, hydra_targets[target_no]->skiplogin[snpi]) == 0)
          snpj = 1;
      if (snpj) {
        if (snp_is_redo == 0) {
          hydra_brains.sent++;
          hydra_targets[target_no]->sent++;
        }
        if (debug)
          printf("[DEBUG] double found for %s == %s, skipping\n", hydra_heads[head_no]->current_login_ptr, hydra_targets[target_no]->skiplogin[snpi - 1]);
        // only if -l/L -p/P with -u and if loginptr was not justed increased
        if ((hydra_options.mode & 64) != 64 && hydra_options.loop_mode == 0 && hydra_targets[target_no]->pass_no > 0) { // -l -P (not! -u)
          // increase login_ptr to next
          hydra_targets[target_no]->login_no++;
          if (hydra_targets[target_no]->login_no < hydra_brains.countlogin) {
            hydra_targets[target_no]->login_ptr++;
            while (*hydra_targets[target_no]->login_ptr != 0)
              hydra_targets[target_no]->login_ptr++;
            hydra_targets[target_no]->login_ptr++;
          }
          // add count
          hydra_brains.sent += hydra_brains.countpass - hydra_targets[target_no]->pass_no;
          hydra_targets[target_no]->sent += hydra_brains.countpass - hydra_targets[target_no]->pass_no;
          // reset password list
          hydra_targets[target_no]->pass_ptr = pass_ptr;
          hydra_targets[target_no]->pass_no = 0;
          hydra_targets[target_no]->pass_state = 0;
        }
        return hydra_send_next_pair(target_no, head_no);        // little trick to keep the code small
      }
    }

    memset(&snpbuf, 0, sizeof(snpbuf));
    strncpy(snpbuf, hydra_heads[head_no]->current_login_ptr, MAXLINESIZE - 3);
    if (strlen(hydra_heads[head_no]->current_login_ptr) > MAXLINESIZE - 3)
      snpbuflen = MAXLINESIZE - 2;
    else
      snpbuflen = strlen(hydra_heads[head_no]->current_login_ptr) + 1;
    strncpy(snpbuf + snpbuflen, hydra_heads[head_no]->current_pass_ptr, MAXLINESIZE - snpbuflen - 1);
    if (strlen(hydra_heads[head_no]->current_pass_ptr) > MAXLINESIZE - snpbuflen - 1)
      snpbuflen += MAXLINESIZE - snpbuflen - 1;
    else
      snpbuflen += strlen(hydra_heads[head_no]->current_pass_ptr) + 1;
    if (snp_is_redo == 0) {
      hydra_brains.sent++;
      hydra_targets[target_no]->sent++;
    } else if (debug)
      printf("[DEBUG] send_next_pair_redo done %d, pass_state %d, clogin %s, cpass %s, tlogin %s, tpass %s, is_redo %d\n",
             snpdone, hydra_targets[target_no]->pass_state, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, hydra_targets[target_no]->login_ptr,
             hydra_targets[target_no]->pass_ptr, snp_is_redo);
    //hydra_dump_data(snpbuf, snpbuflen, "SENT");
    fck = write(hydra_heads[head_no]->sp[0], snpbuf, snpbuflen);
    if (fck < snpbuflen) {
      if (verbose)
        fprintf(stderr, "[ERROR] can not write to child %d, restarting it ...\n", head_no);
      hydra_increase_fail_count(target_no, head_no);
      loop_cnt = 0;
      return 0;                 // not prevent disabling it, if its needed its already done in the above line
    }
    if (debug || hydra_options.showAttempt) {
      printf("[%sATTEMPT] target %s - login \"%s\" - pass \"%s\" - %lu of %lu [child %d]\n",
             hydra_targets[target_no]->redo_state ? "REDO-" : snp_is_redo ? "RE-" : "", hydra_targets[target_no]->target, hydra_heads[head_no]->current_login_ptr,
             hydra_heads[head_no]->current_pass_ptr, hydra_targets[target_no]->sent, hydra_brains.todo + hydra_targets[target_no]->redo, head_no);
    }
    loop_cnt = 0;
    return 0;
  }
  loop_cnt = 0;
  return -1;
}

void hydra_skip_user(int target_no, char *username) {
  int i;

  if (username == NULL || *username == 0)
    return;

  // double check
  for (i = 0; i < hydra_targets[target_no]->skipcnt; i++)
    if (strcmp(username, hydra_targets[target_no]->skiplogin[i]) == 0)
      return;

  if (hydra_targets[target_no]->skipcnt < SKIPLOGIN && (hydra_targets[target_no]->skiplogin[hydra_targets[target_no]->skipcnt] = malloc(strlen(username) + 1)) != NULL) {
    strcpy(hydra_targets[target_no]->skiplogin[hydra_targets[target_no]->skipcnt], username);
    hydra_targets[target_no]->skipcnt++;
  }
  if (hydra_options.loop_mode == 0 && (hydra_options.mode & 64) != 64) {
    if (memcmp(username, hydra_targets[target_no]->login_ptr, strlen(username)) == 0) {
      if (debug)
        printf("[DEBUG] skipping username %s\n", username);
      // increase count
      hydra_brains.sent += hydra_brains.countpass - hydra_targets[target_no]->pass_no;
      hydra_targets[target_no]->sent += hydra_brains.countpass - hydra_targets[target_no]->pass_no;
      // step to next login
      hydra_targets[target_no]->login_no++;
      if (hydra_targets[target_no]->login_no < hydra_brains.countlogin) {
        hydra_targets[target_no]->login_ptr++;
        while (*hydra_targets[target_no]->login_ptr != 0)
          hydra_targets[target_no]->login_ptr++;
        hydra_targets[target_no]->login_ptr++;
      }
      // reset password state
      hydra_targets[target_no]->pass_ptr = pass_ptr;
      hydra_targets[target_no]->pass_no = 0;
      hydra_targets[target_no]->pass_state = 0;
    }
  }
}

int hydra_check_for_exit_condition() {
  int i, k = 0;

  if (hydra_brains.exit) {
    if (debug)
      printf("[DEBUG] exit was forced\n");
    return -1;
  }
  if (hydra_brains.targets <= hydra_brains.finished && hydra_brains.active < 1) {
    if (debug)
      printf("[DEBUG] all targets done and all heads finished\n");
    return 1;
  }
  if (hydra_brains.active < 1) {
    // no head active?! check if they are all disabled, if so, we are done
    for (i = 0; i < hydra_options.max_use && k == 0; i++)
      if (hydra_heads[i]->active >= 0)
        k = 1;
    if (k == 0) {
      fprintf(stderr, "[ERROR] all children were disabled due too many connection errors\n");
      return -1;
    }
  }
  return 0;
}

int hydra_select_target() {
  int target_no = -1, i, j = -1000;

  for (i = 0; i < hydra_brains.targets; i++)
    if (hydra_targets[i]->use_count < hydra_options.tasks && hydra_targets[i]->done == 0)
      if (j < hydra_options.tasks - hydra_targets[i]->failed - hydra_targets[i]->use_count) {
        target_no = i;
        j = hydra_options.tasks - hydra_targets[i]->failed - hydra_targets[i]->use_count;
      }
  return target_no;
}

int main(int argc, char *argv[]) {
  char *proxy_string = NULL, *device = NULL, *memcheck;
  FILE *lfp = NULL, *pfp = NULL, *cfp = NULL, *ifp = NULL, *rfp = NULL;
  size_t countinfile = 1, sizeinfile = 0;
  unsigned long int math2;
  int i = 0, j = 0, k, error = 0, modusage = 0;
  int head_no = 0, target_no = 0, exit_condition = 0, readres;
  time_t starttime, elapsed_status, elapsed_restore, status_print = 59, tmp_time;
  char *tmpptr, *tmpptr2;
  char rc, buf[MAXBUF];
  fd_set fdreadheads;
  int max_fd;
  struct addrinfo hints, *res, *p;
  struct sockaddr_in6 *ipv6 = NULL;
  struct sockaddr_in *ipv4 = NULL;

  printf("%s %s (c) 2014 by %s - Please do not use in military or secret service organizations, or for illegal purposes.\n\n", PROGRAM, VERSION, AUTHOR);
#ifndef LIBPOSTGRES
  SERVICES = hydra_string_replace(SERVICES, "postgres ", "");
  strcat(unsupported, "postgres ");
#endif
#ifndef LIBSAPR3
  SERVICES = hydra_string_replace(SERVICES, "sapr3 ", "");
  strcat(unsupported, "sapr3 ");
#endif
#ifndef LIBFIREBIRD
  SERVICES = hydra_string_replace(SERVICES, "firebird ", "");
  strcat(unsupported, "firebird ");
#endif
#ifndef LIBAFP
  SERVICES = hydra_string_replace(SERVICES, "afp ", "");
  strcat(unsupported, "afp ");
#endif
#ifndef LIBNCP
  SERVICES = hydra_string_replace(SERVICES, "ncp ", "");
  strcat(unsupported, "ncp ");
#endif
#ifndef LIBSSH
  SERVICES = hydra_string_replace(SERVICES, "ssh ", "");
  strcat(unsupported, "ssh ");
  SERVICES = hydra_string_replace(SERVICES, "sshkey ", "");
  strcat(unsupported, "sshkey ");
#endif
#ifndef LIBSVN
  SERVICES = hydra_string_replace(SERVICES, "svn ", "");
  strcat(unsupported, "svn ");
#endif
#ifndef LIBORACLE
  SERVICES = hydra_string_replace(SERVICES, "oracle ", "");
  strcat(unsupported, "oracle ");
#endif
#ifndef LIBMYSQLCLIENT
  SERVICES = hydra_string_replace(SERVICES, "mysql ", "mysql(v4) ");
  strcat(unsupported, "mysql5 ");
#endif
#ifndef LIBOPENSSL
  // for ftps
  SERVICES = hydra_string_replace(SERVICES, " ftps", "");
  // for pop3
  SERVICES = hydra_string_replace(SERVICES, "pop3[s]", "pop3");
  // for imap
  SERVICES = hydra_string_replace(SERVICES, "imap[s]", "imap");
  // for smtp
  SERVICES = hydra_string_replace(SERVICES, "smtp[s]", "smtp");
  // for telnet
  SERVICES = hydra_string_replace(SERVICES, "telnet[s]", "telnet");
  // for http[s]-{head|get}
  SERVICES = hydra_string_replace(SERVICES, "http[s]", "http");
  // for http[s]-{get|post}-form
  SERVICES = hydra_string_replace(SERVICES, "http[s]", "http");
  // for ldap3
  SERVICES = hydra_string_replace(SERVICES, "[-{cram|digest}md5]", "");
  // for sip
  SERVICES = hydra_string_replace(SERVICES, " sip", "");
  // for rdp
  SERVICES = hydra_string_replace(SERVICES, " rdp", "");
  // for oracle-listener
  SERVICES = hydra_string_replace(SERVICES, " oracle-listener", "");
  // general
  SERVICES = hydra_string_replace(SERVICES, "[s]", "");
  // for oracle-sid
  SERVICES = hydra_string_replace(SERVICES, " oracle-sid", "");
  strcat(unsupported, "SSL-services (ftps, sip, rdp, oracle-services, ...) ");
#endif
#ifndef HAVE_MATH_H
  if (strlen(unsupported) > 0)
    strcat(unsupported, "and ");
  strcat(unsupported, "password bruteforce generation ");
#endif
#ifndef HAVE_PCRE
  if (strlen(unsupported) > 0)
    strcat(unsupported, "and ");
  strcat(unsupported, "regex support ");
#endif

  (void) setvbuf(stdout, NULL, _IONBF, 0);
  (void) setvbuf(stderr, NULL, _IONBF, 0);
  // set defaults 
  memset(&hydra_options, 0, sizeof(hydra_options));
  memset(&hydra_brains, 0, sizeof(hydra_brains));
  prg = argv[0];
  hydra_options.debug = debug = 0;
  hydra_options.verbose = verbose = 0;
  found = 0;
  use_proxy = 0;
  proxy_string_ip[0] = 0;
  proxy_string_port = 0;
  strcpy(proxy_string_type, "connect");
  proxy_authentication = cmdlinetarget = NULL;
  hydra_options.login = NULL;
  hydra_options.loginfile = NULL;
  hydra_options.pass = NULL;
  hydra_options.passfile = NULL;
  hydra_options.tasks = TASKS;
  hydra_options.max_use = MAXTASKS;
  hydra_brains.ofp = stdout;
  hydra_brains.targets = 1;
  hydra_options.waittime = waittime = WAITTIME;

  // command line processing
  if (argc > 1 && strncmp(argv[1], "-h", 2) == 0)
    help(1);
  if (argc < 2)
    help(0);
  while ((i = getopt(argc, argv, "hq64Rde:vVl:fFg:L:p:P:o:M:C:t:T:m:w:W:s:SUux:")) >= 0) {
    switch (i) {
    case 'h':
      help(1);
      break;
    case 'q':
      quiet = 1;
      break;
    case 'u':
      hydra_options.loop_mode = 1;
      break;
    case '6':
      prefer_ipv6 = 1;
      break;
    case '4':
      prefer_ipv6 = 0;
      break;
    case 'R':
      hydra_options.restore = 1;
      break;
    case 'd':
      hydra_options.debug = debug = 1;
      ++verbose;
      break;
    case 'e':
      i = 0;
      while (i < strlen(optarg)) {
        switch (optarg[i]) {
        case 'r':
          hydra_options.try_password_reverse_login = 1;
          hydra_options.mode = hydra_options.mode | 8;
          break;
        case 'n':
          hydra_options.try_null_password = 1;
          hydra_options.mode = hydra_options.mode | 16;
          break;
        case 's':
          hydra_options.try_password_same_as_login = 1;
          hydra_options.mode = hydra_options.mode | 32;
          break;
        default:
          fprintf(stderr, "[ERROR] unknown mode %c for option -e, only supporting \"n\", \"s\" and \"r\"\n", optarg[i]);
          exit(-1);
        }
        i++;
      }
      break;
    case 'v':
      hydra_options.verbose = verbose = 1;
      break;
    case 'V':
      hydra_options.showAttempt = 1;
      break;
    case 'l':
      hydra_options.login = optarg;
      break;
    case 'L':
      hydra_options.loginfile = optarg;
      hydra_options.mode = hydra_options.mode | 2;
      break;
    case 'p':
      hydra_options.pass = optarg;
      break;
    case 'P':
      hydra_options.passfile = optarg;
      hydra_options.mode = hydra_options.mode | 1;
      break;
    case 'f':
      hydra_options.exit_found = 1;
      break;
    case 'F':
      hydra_options.exit_found = 2;
      break;
    case 'o':
      hydra_options.outfile_ptr = optarg;
//      colored_output = 0;
      break;
    case 'M':
      hydra_options.infile_ptr = optarg;
      break;
    case 'C':
      hydra_options.colonfile = optarg;
      hydra_options.mode = 64;
      break;
    case 'm':
      hydra_options.miscptr = optarg;
      break;
    case 'w':
      hydra_options.waittime = waittime = atoi(optarg);
      if (waittime < 1) {
        fprintf(stderr, "[ERROR] waittime must be larger than 0\n");
        exit(-1);
      } else if (waittime < 5)
        fprintf(stderr, "[WARNING] the waittime you set is low, this can result in errornous results\n");
      break;
    case 'W':
      hydra_options.conwait = conwait = atoi(optarg);
      break;
    case 's':
      hydra_options.port = port = atoi(optarg);
      break;
    case 'S':
#ifndef LIBOPENSSL
      fprintf(stderr, "[WARNING] hydra was compiled without SSL support. Install openssl and recompile! Option ignored...\n");
      hydra_options.ssl = 0;
      break;
#else
      hydra_options.ssl = 1;
      break;
#endif
    case 't':
      hydra_options.tasks = atoi(optarg);
      break;
    case 'T':
      hydra_options.max_use = atoi(optarg);
      break;
    case 'U':
      modusage = 1;
      break;
    case 'x':
#ifndef HAVE_MATH_H
      fprintf(stderr, "[ERROR] -x option is not available as math.h was not found at compile time\n");
      exit(-1);
#else
      if (strcmp(optarg, "-h") == 0)
        help_bfg();
      bf_options.arg = optarg;
      hydra_options.bfg = 1;
      hydra_options.mode = hydra_options.mode | 4;
      hydra_options.loop_mode = 1;
      break;
#endif
    default:
      exit(-1);
    }
  }

  //check if output is redirected from the shell or in a file
  if (colored_output && !isatty(fileno(stdout)))
    colored_output = 0;

#ifdef LIBNCURSES
  //then check if the term is color enabled using ncurses lib
  if (colored_output) {
    if (!setupterm(NULL, 1, NULL) && (tigetnum("colors") <= 0)) {
      colored_output = 0;
    }
  }
#else
  //don't want border line effect so disabling color output
  //if we are not sure about the term
  colored_output = 0;
#endif

  if (debug)
    printf("[DEBUG] Ouput color flag is %d\n", colored_output);

  if (hydra_options.restore && argc > 2 + debug + verbose)
    bail("no option may be supplied together with -R");

  printf("%s (%s) starting at %s\n", PROGRAM, RESOURCE, hydra_build_time());
  if (debug) {
    printf("[DEBUG] cmdline: ");
    for (i = 0; i < argc; i++)
      printf("%s ", argv[i]);
    printf("\n");
  }
  if (hydra_options.login != NULL && hydra_options.loginfile != NULL)
    bail("You can only use -L OR -l, not both\n");
  if (hydra_options.pass != NULL && hydra_options.passfile != NULL)
    bail("You can only use -P OR -p, not both\n");
  if (hydra_options.restore) {
    hydra_restore_read();
    // stuff we have to copy from the non-restore part 
    if (strncmp(hydra_options.service, "http-", 5) == 0) {
      if (getenv("HYDRA_PROXY_HTTP") && getenv("HYDRA_PROXY"))
        bail("Found HYDRA_PROXY_HTTP *and* HYDRA_PROXY environment variables - you can use only ONE for the service http-head/http-get!");
      if (getenv("HYDRA_PROXY_HTTP")) {
        printf("[INFO] Using HTTP Proxy: %s\n", getenv("HYDRA_PROXY_HTTP"));
        use_proxy = 1;
      }
    }
  } else {                      // normal mode, aka non-restore mode 
    if (hydra_options.colonfile)
      hydra_options.loop_mode = 0;      // just to be sure
    if (hydra_options.infile_ptr != NULL) {
      if (optind + 2 < argc)
        bail("The -M FILE option can not be used together with a host on the commandline");
      if (optind + 1 > argc)
        bail("You need to define a service to attack");
      if (optind + 2 == argc)
        fprintf(stderr, "[WARNING] With the -M FILE option you can not specify a server on the commandline. Lets hope you did everything right!\n");
      hydra_options.server = NULL;
      hydra_options.service = argv[optind];
      if (optind + 2 == argc)
        hydra_options.miscptr = argv[optind + 1];
    } else if (optind + 2 != argc && optind + 3 != argc && optind < argc) {
      // check if targetdef follow syntax <service-name>://<target>[:<port-number>][/<parameters>] or it's a syntax error 
      char *targetdef = strdup(argv[optind]);
      char *service_pos, *target_pos, *port_pos = NULL, *param_pos = NULL;

      if ((targetdef != NULL) && (strstr(targetdef, "://") != NULL)) {
        service_pos = strstr(targetdef, "://");
        if ((service_pos - targetdef) == 0)
          bail("could not identify service");
        if ((hydra_options.service = malloc(1 + service_pos - targetdef)) == NULL)
          bail("could not alloc memory");
        strncpy(hydra_options.service, targetdef, service_pos - targetdef);
        hydra_options.service[service_pos - targetdef] = 0;
        target_pos = targetdef + (service_pos - targetdef + 3);

        if (*target_pos == '[') {
          target_pos++;
          if ((param_pos = index(target_pos, ']')) == NULL)
            bail("no closing ']' found in target definition");
          *param_pos++ = 0;
          if (*param_pos == ':')
            port_pos = ++param_pos;
          if ((param_pos = index(param_pos, '/')) != NULL)
            *param_pos++ = 0;
        } else {
          port_pos = index(target_pos, ':');
          param_pos = index(target_pos, '/');
          if (port_pos != NULL && param_pos != NULL && port_pos > param_pos)
            port_pos = NULL;
          if (port_pos != NULL)
            *port_pos++ = 0;
          if (param_pos != NULL)
            *param_pos++ = 0;
          if (port_pos != NULL && index(port_pos, ':') != NULL) {
            if (prefer_ipv6)
              bail("Illegal IPv6 target definition must be written within '[' ']'");
            else
              bail("Illegal port definition");
          }
        }
        if (*target_pos == 0)
          hydra_options.server = NULL;
        else
          hydra_options.server = target_pos;
        if (port_pos != NULL)
          hydra_options.port = port = atoi(port_pos);
        if (param_pos != NULL) {
          if (strstr(hydra_options.service, "http") != NULL && strstr(hydra_options.service, "http-proxy") == NULL && param_pos[1] != '/')
            *--param_pos = '/';
          hydra_options.miscptr = param_pos;
        }
//printf("target: %s  service: %s  port: %s  opt: %s\n", target_pos, hydra_options.service, port_pos, param_pos);
        if (debug)
          printf("[DEBUG] opt:%d argc:%d mod:%s tgt:%s port:%d misc:%s\n", optind, argc, hydra_options.service, hydra_options.server, hydra_options.port, hydra_options.miscptr);
      } else {
        hydra_options.server = NULL;
        hydra_options.service = NULL;

        if (modusage)
          hydra_options.service = targetdef;
        else
          help(0);
      }
    } else {
      hydra_options.server = argv[optind];
      cmdlinetarget = argv[optind];
      hydra_options.service = argv[optind + 1];
      if (optind + 3 == argc)
        hydra_options.miscptr = argv[optind + 2];
    }

    if (strcmp(hydra_options.service, "pop3s") == 0 || strcmp(hydra_options.service, "smtps") == 0 || strcmp(hydra_options.service, "imaps") == 0
        || strcmp(hydra_options.service, "telnets") == 0 || (strncmp(hydra_options.service, "ldap", 4) == 0 && hydra_options.service[strlen(hydra_options.service) - 1] == 's')) {
      hydra_options.ssl = 1;
      hydra_options.service[strlen(hydra_options.service) - 1] = 0;
    }

    if (getenv("HYDRA_PROXY_HTTP") || getenv("HYDRA_PROXY")) {
      if (strcmp(hydra_options.service, "afp") == 0 || strcmp(hydra_options.service, "firebird") == 0 || strncmp(hydra_options.service, "mysql", 5) == 0 ||
          strcmp(hydra_options.service, "ncp") == 0 || strcmp(hydra_options.service, "oracle") == 0 || strcmp(hydra_options.service, "postgres") == 0 ||
          strncmp(hydra_options.service, "ssh", 3) == 0 || strcmp(hydra_options.service, "sshkey") == 0 || strcmp(hydra_options.service, "svn") == 0 ||
          strcmp(hydra_options.service, "sapr3") == 0) {
        fprintf(stderr, "[WARNING] module %s does not support HYDRA_PROXY* !\n", hydra_options.service);
        proxy_string = NULL;
      }
    }

    /* here start the services */

    if (strcmp(hydra_options.service, "ssl") == 0 || strcmp(hydra_options.service, "www") == 0 || strcmp(hydra_options.service, "http") == 0
        || strcmp(hydra_options.service, "https") == 0) {
      fprintf(stderr, "[WARNING] The service http has been replaced with http-head and http-get, using by default GET method. Same for https.\n");
      if (strcmp(hydra_options.service, "http") == 0) {
        hydra_options.service = malloc(strlen("http-get") + 1);
        strcpy(hydra_options.service, "http-get");
      }
      if (strcmp(hydra_options.service, "https") == 0) {
        hydra_options.service = malloc(strlen("https-get") + 1);
        strcpy(hydra_options.service, "https-get");
      }
    }

    if (strcmp(hydra_options.service, "http-form-get") == 0)
      strcpy(hydra_options.service, "http-get-form");
    if (strcmp(hydra_options.service, "https-form-get") == 0)
      strcpy(hydra_options.service, "https-get-form");
    if (strcmp(hydra_options.service, "http-form-post") == 0)
      strcpy(hydra_options.service, "http-post-form");
    if (strcmp(hydra_options.service, "https-form-post") == 0)
      strcpy(hydra_options.service, "https-post-form");

    if (modusage == 1)
      module_usage();

    i = 0;
    if (strcmp(hydra_options.service, "telnet") == 0) {
      fprintf(stderr, "[WARNING] telnet is by its nature unreliable to analyze, if possible better choose FTP, SSH, etc. if available\n");
      i = 1;
    }
    if (strcmp(hydra_options.service, "ftp") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "ftps") == 0) {
      fprintf(stderr, "[WARNING] you enabled ftp-SSL (auth tls) mode. If you want to use direct SSL ftp, use -S and the ftp module instead.\n");
      i = 1;
    }
    if (strcmp(hydra_options.service, "pop3") == 0) {
      fprintf(stderr, "[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!\n");
      i = 1;
    }
    if (strcmp(hydra_options.service, "imap") == 0) {
      fprintf(stderr, "[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!\n");
      i = 1;
    }
    if (strcmp(hydra_options.service, "redis") == 0)
      i = 2;
    if (strcmp(hydra_options.service, "asterisk") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "vmauthd") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "rexec") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "rlogin") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "rsh") == 0)
      i = 3;
    if (strcmp(hydra_options.service, "nntp") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "socks5") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "icq") == 0) {
      fprintf(stderr, "[WARNING] The icq module is not working with the modern protocol version! (somebody else will need to fix this as I don't care for icq)\n");
      i = 1;
    }
    if (strcmp(hydra_options.service, "mysql") == 0) {
      i = 1;
      if (hydra_options.tasks > 4) {
        fprintf(stderr, "[INFO] Reduced number of tasks to 4 (mysql does not like many parallel connections)\n");
        hydra_options.tasks = 4;
      }
    }
    if (strcmp(hydra_options.service, "mssql") == 0)
      i = 1;
    if ((strcmp(hydra_options.service, "oracle-listener") == 0) || (strcmp(hydra_options.service, "tns") == 0)) {
      i = 2;
      hydra_options.service = malloc(strlen("oracle-listener") + 1);
      strcpy(hydra_options.service, "oracle-listener");
    }
    if ((strcmp(hydra_options.service, "oracle-sid") == 0) || (strcmp(hydra_options.service, "sid") == 0)) {
      i = 3;
      hydra_options.service = malloc(strlen("oracle-sid") + 1);
      strcpy(hydra_options.service, "oracle-sid");
    }
#ifdef LIBORACLE
    if ((strcmp(hydra_options.service, "oracle") == 0) || (strcmp(hydra_options.service, "ora") == 0)) {
      i = 1;
      hydra_options.service = malloc(strlen("oracle") + 1);
      strcpy(hydra_options.service, "oracle");
    }
#endif
    if (strcmp(hydra_options.service, "postgres") == 0)
#ifdef LIBPOSTGRES
      i = 1;
#else
      bail("Compiled without LIBPOSTGRES support, module not available!");
#endif
    if (strcmp(hydra_options.service, "firebird") == 0)
#ifdef LIBFIREBIRD
      i = 1;
#else
      bail("Compiled without LIBFIREBIRD support, module not available!");
#endif
    if (strcmp(hydra_options.service, "afp") == 0)
#ifdef LIBAFP
      i = 1;
#else
      bail("Compiled without LIBAFP support, module not available!");
#endif
    if (strcmp(hydra_options.service, "svn") == 0)
#ifdef LIBSVN
      i = 1;
#else
      bail("Compiled without LIBSVN support, module not available!");
#endif
    if (strcmp(hydra_options.service, "ncp") == 0)
#ifdef LIBNCP
      i = 1;
#else
      bail("Compiled without LIBNCP support, module not available!");
#endif
    if (strcmp(hydra_options.service, "pcanywhere") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "http-proxy") == 0) {
      i = 1;
      if (hydra_options.miscptr != NULL && strncmp(hydra_options.miscptr, "http://", 7) != 0)

        bail("module option must start with http://");
    }
    if (strcmp(hydra_options.service, "cvs") == 0) {
      i = 1;
      if (hydra_options.miscptr == NULL || (strlen(hydra_options.miscptr) == 0)) {
        fprintf(stderr, "[INFO] The CVS repository path wasn't passed so using /root by default\n");
      }
    }
    if (strcmp(hydra_options.service, "svn") == 0) {
      i = 1;
      if (hydra_options.miscptr == NULL || (strlen(hydra_options.miscptr) == 0)) {
        fprintf(stderr, "[INFO] The SVN repository path wasn't passed so using /trunk by default\n");
      }
    }
    if (strcmp(hydra_options.service, "ssh") == 0 || strcmp(hydra_options.service, "sshkey") == 0) {
      if (hydra_options.tasks > 8)
        fprintf(stderr, "[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4\n");
#ifdef LIBSSH
      i = 1;
#else
      bail("Compiled without LIBSSH v0.4.x support, module is not available!");
#endif
    }
    if (strcmp(hydra_options.service, "smtp") == 0) {
      fprintf(stderr, "[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!\n");
      i = 1;
    }
    if (strcmp(hydra_options.service, "smtp-enum") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "teamspeak") == 0)
      i = 1;
    if ((strcmp(hydra_options.service, "smb") == 0) || (strcmp(hydra_options.service, "smbnt") == 0)) {
      if (hydra_options.tasks > 1) {
        fprintf(stderr, "[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)\n");
        hydra_options.tasks = 1;
      }
      i = 1;
    }
    if ((strcmp(hydra_options.service, "smb") == 0) || (strcmp(hydra_options.service, "smbnt") == 0)) {
#ifdef LIBOPENSSL
      if (hydra_options.tasks > 1) {
        fprintf(stderr, "[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)\n");
        hydra_options.tasks = 1;
      }
      i = 1;
#endif
    }
    if ((strcmp(hydra_options.service, "smb") == 0) || (strcmp(hydra_options.service, "smbnt") == 0) ||
        (strcmp(hydra_options.service, "sip") == 0) || (strcmp(hydra_options.service, "rdp") == 0) ||
        (strcmp(hydra_options.service, "oracle-listener") == 0) || (strcmp(hydra_options.service, "oracle-sid") == 0)) {
#ifndef LIBOPENSSL
      bail("Compiled without OPENSSL support, module not available!");
#endif
    }
    if (strcmp(hydra_options.service, "pcnfs") == 0) {
      i = 1;
      if (port == 0)
        bail("You must set the port for pcnfs with -s (run \"rpcinfo -p %s\" and look for the pcnfs v2 UDP port)");
    }
    if (strcmp(hydra_options.service, "sapr3") == 0) {
#ifdef LIBSAPR3
      i = 1;
      if (port == PORT_SAPR3)
        bail("You must set the port for sapr3 with -s <port>, it should lie between 3200 and 3699.");
      if (port < 3200 || port > 3699)
        fprintf(stderr, "[WARNING] The port is not in the range 3200 to 3399 - please ensure it is ok!\n");
      if (hydra_options.miscptr == NULL || atoi(hydra_options.miscptr) < 0 || atoi(hydra_options.miscptr) > 999 || !isdigit(hydra_options.miscptr[0]))
        bail("You must set the client ID (0-999) as an additional option or via -m");
#else
      bail("Compiled without LIBSAPR3 support, module not available!");
#endif
    }
    if (strcmp(hydra_options.service, "cisco") == 0) {
      i = 2;
      if (hydra_options.tasks > 4)
        fprintf(stderr, "[WARNING] you should set the number of parallel task to 4 for cisco services.\n");
    }
    if (strncmp(hydra_options.service, "snmpv", 5) == 0) {
      hydra_options.service[4] = hydra_options.service[5];
      hydra_options.service[5] = 0;
    }
    if (strcmp(hydra_options.service, "snmp") == 0 || strcmp(hydra_options.service, "snmp1") == 0) {
      hydra_options.service[4] = 0;
      i = 2;
    }
    if (strcmp(hydra_options.service, "snmp2") == 0 || strcmp(hydra_options.service, "snmp3") == 0) {
      if (hydra_options.miscptr == NULL)
        hydra_options.miscptr = strdup(hydra_options.service + 4);
      else {
        tmpptr = malloc(strlen(hydra_options.miscptr) + 4);
        strcpy(tmpptr, hydra_options.miscptr);
        strcat(tmpptr, ":");
        strcat(tmpptr, hydra_options.service + 4);
        hydra_options.miscptr = tmpptr;
      }
      hydra_options.service[4] = 0;
      i = 2;
    }
    if (strcmp(hydra_options.service, "snmp") == 0 && hydra_options.miscptr != NULL) {
      char *lptr;

      j = 1;
      tmpptr = strdup(hydra_options.miscptr);
      lptr = strtok(tmpptr, ":");
      while (lptr != NULL) {
        i = 0;
        if (strcasecmp(lptr, "1") == 0 || strcasecmp(lptr, "2") == 0 || strcasecmp(lptr, "3") == 0) {
          i = 1;
          j = lptr[0] - '0' + (j & 252);
        } else if (strcasecmp(lptr, "READ") == 0 || strcasecmp(lptr, "WRITE") == 0 || strcasecmp(lptr, "PLAIN") == 0)
          i = 1;
        else if (strcasecmp(lptr, "MD5") == 0) {
          i = 1;
          j = 4 + (j & 51);
        } else if (strcasecmp(lptr, "SHA") == 0 || strcasecmp(lptr, "SHA1") == 0) {
          i = 1;
          j = 8 + (j & 51);
        } else if (strcasecmp(lptr, "DES") == 0) {
          i = 1;
          j = 16 + (j & 15);
        } else if (strcasecmp(lptr, "AES") == 0) {
          i = 1;
          j = 32 + (j & 15);
        }
        if (i == 0) {
          fprintf(stderr, "[ERROR] unknown parameter in module option: %s\n", lptr);
          exit(-1);
        }
        lptr = strtok(NULL, ":");
      }
      i = 2;
      if ((j & 3) < 3 && j > 2)
        fprintf(stderr, "[WARNING] SNMPv1 and SNMPv2 do not support hash and encryption, ignored\n");
      if ((j & 3) == 3) {
        fprintf(stderr, "[WARNING] SNMPv3 is still in beta state, use at own risk and report problems\n");
        if (j >= 16)
          bail("The SNMPv3 module so far only support authentication (md5/sha), not yet encryption\n");
        if (hydra_options.colonfile == NULL
            && ((hydra_options.login == NULL && hydra_options.loginfile == NULL) || (hydra_options.pass == NULL && hydra_options.passfile == NULL && hydra_options.bfg == 0))) {
          if (j > 3) {
            fprintf(stderr,
                    "[ERROR] you specified SNMPv3, defined hashing/encryption but only gave one of login or password list. Either supply both logins and passwords (this is what is usually used in SNMPv3), or remove the hashing/encryption option (unusual)\n");
            exit(-1);
          }
          fprintf(stderr, "[WARNING] you specified SNMPv3 but gave no logins, NoAuthNoPriv is assumed. This is an unusual case, you should know what you are doing\n");
          tmpptr = malloc(strlen(hydra_options.miscptr) + 8);
          strcpy(tmpptr, hydra_options.miscptr);
          strcat(tmpptr, ":");
          strcat(tmpptr, "PLAIN");
          hydra_options.miscptr = tmpptr;
        } else {
          i = 1;                // snmpv3 with login+pass mode
#ifndef LIBOPENSSL
          bail("hydra was not compiled with OPENSSL support, snmpv3 can only be used on NoAuthNoPriv mode (only logins, no passwords)!");
#endif
          printf("[INFO] Using %s SNMPv3 with %s authentication and %s privacy\n", j > 16 ? "AuthPriv" : "AuthNoPriv", (j & 8) == 8 ? "SHA" : "MD5",
                 (j & 16) == 16 ? "DES" : (j > 16) ? "AES" : "no");
        }
      }
    }
    if (strcmp(hydra_options.service, "sip") == 0) {
      if (hydra_options.miscptr == NULL) {
        if (hydra_options.server != NULL) {
          hydra_options.miscptr = hydra_options.server;
          i = 1;
        } else {
          bail("The sip module does not work with multiple servers (-M)\n");
        }
      } else {
        i = 1;
      }
    }
    if (strcmp(hydra_options.service, "ldap") == 0) {
      bail("Please select ldap2 or ldap3 for simple authentication or ldap3-crammd5 or ldap3-digestmd5\n");
    }
    if (strcmp(hydra_options.service, "ldap2") == 0 || strcmp(hydra_options.service, "ldap3") == 0) {
      i = 1;
      if ((hydra_options.miscptr != NULL && hydra_options.login != NULL)
          || (hydra_options.miscptr != NULL && hydra_options.loginfile != NULL) || (hydra_options.login != NULL && hydra_options.loginfile != NULL))
        bail("you may only use one of -l, -L or -m\n");
      if (hydra_options.login == NULL && hydra_options.loginfile == NULL && hydra_options.miscptr == NULL)
        fprintf(stderr, "[WARNING] no DN to authenticate is defined, using DN of null (use -m, -l or -L to define DNs)\n");
      if (hydra_options.login == NULL && hydra_options.loginfile == NULL) {
        i = 2;
      }
    }
    if (strcmp(hydra_options.service, "ldap3-crammd5") == 0 || strcmp(hydra_options.service, "ldap3-digestmd5") == 0) {
      i = 1;
      if (hydra_options.login == NULL && hydra_options.loginfile == NULL)
        bail("-l or -L option is required to specify the login\n");
      if (hydra_options.miscptr == NULL)
        bail("-m option is required to specify the DN\n");
    }
// ADD NEW SERVICES HERE 
    if (strcmp(hydra_options.service, "s7-300") == 0) {
      if (hydra_options.tasks > 8) {
        fprintf(stderr, "[INFO] Reduced number of tasks to 8 (the PLC does not like more connections)\n");
        hydra_options.tasks = 8;
      }
      i = 2;
    }
    if (strcmp(hydra_options.service, "cisco-enable") == 0) {
      i = 2;
      if (hydra_options.login == NULL) {
        //hydra_options.login = empty_login;
        i = 1;                  // login will be the initial Username: login, or line Password:
      }
      if (hydra_options.miscptr == NULL) {
        fprintf(stderr, "[WARNING] You did not supply the initial support to the Cisco via -l, assuming direct console access\n");
      }
      if (hydra_options.tasks > 4)
        fprintf(stderr, "[WARNING] you should set the number of parallel task to 4 for cisco enable services.\n");
    }
    if (strcmp(hydra_options.service, "http-proxy-urlenum") == 0) {
      i = 4;
      hydra_options.pass = empty_login;
      if (hydra_options.miscptr == NULL) {
        fprintf(stderr, "[WARNING] You did not supply proxy credentials via the optional parameter\n");
      }
      if (hydra_options.bfg || hydra_options.passfile != NULL)
        bail("the http-proxy-urlenum does not need the -p/-P or -x option");
    }
    if (strcmp(hydra_options.service, "vnc") == 0) {
      i = 2;
      if (hydra_options.tasks > 4)
        fprintf(stderr, "[WARNING] you should set the number of parallel task to 4 for vnc services.\n");
    }
    if (strcmp(hydra_options.service, "https-head") == 0 || strcmp(hydra_options.service, "https-get") == 0) {
#ifdef LIBOPENSSL
      i = 1;
      hydra_options.ssl = 1;
      if (strcmp(hydra_options.service, "https-head") == 0)
        strcpy(hydra_options.service, "http-head");
      else
        strcpy(hydra_options.service, "http-get");
#else
      bail("Compiled without SSL support, module not available");
#endif
    }
    if (strcmp(hydra_options.service, "http-get") == 0 || strcmp(hydra_options.service, "http-head") == 0) {
      i = 1;
      if (hydra_options.miscptr == NULL) {
        fprintf(stderr, "[WARNING] You must supply the web page as an additional option or via -m, default path set to /\n");
        hydra_options.miscptr = malloc(2);
        hydra_options.miscptr = "/";
      }
      if (*hydra_options.miscptr != '/' && strstr(hydra_options.miscptr, "://") == NULL)
        bail("The web page you supplied must start with a \"/\", \"http://\" or \"https://\", e.g. \"/protected/login\"");
      if (getenv("HYDRA_PROXY_HTTP") && getenv("HYDRA_PROXY"))
        bail("Found HYDRA_PROXY_HTTP *and* HYDRA_PROXY environment variables - you can use only ONE for the service http-head/http-get!");
      if (getenv("HYDRA_PROXY_HTTP")) {
        printf("[INFO] Using HTTP Proxy: %s\n", getenv("HYDRA_PROXY_HTTP"));
        use_proxy = 1;
      }
      if (strcmp(hydra_options.service, "http-head") == 0)
        fprintf(stderr, "[WARNING] http-head auth does not work with every server, better use http-get\n");
    }

    if (strcmp(hydra_options.service, "http-get-form") == 0 || strcmp(hydra_options.service, "http-post-form") == 0 || strcmp(hydra_options.service, "https-get-form") == 0
        || strcmp(hydra_options.service, "https-post-form") == 0) {
      char bufferurl[1024], *url, *variables, *cond, *optional1;

      if (strncmp(hydra_options.service, "http-", 5) == 0) {
        i = 1;
      } else {                  // https
#ifdef LIBOPENSSL
        i = 1;
        hydra_options.ssl = 1;
        if (strcmp(hydra_options.service, "https-post-form") == 0)
          strcpy(hydra_options.service, "http-post-form");
        else
          strcpy(hydra_options.service, "http-get-form");
#else
        bail("Compiled without SSL support, module not available");
#endif
      }
      if (hydra_options.miscptr == NULL) {
        fprintf(stderr, "[WARNING] You must supply the web page as an additional option or via -m, default path set to /\n");
        hydra_options.miscptr = malloc(2);
        hydra_options.miscptr = "/";
      }
      //if (*hydra_options.miscptr != '/' && strstr(hydra_options.miscptr, "://") == NULL)
      //  bail("The web page you supplied must start with a \"/\", \"http://\" or \"https://\", e.g. \"/protected/login\"");
      if (hydra_options.miscptr[0] != '/')
        bail("optional parameter must start with a '/' slash!\n");
      if (getenv("HYDRA_PROXY_HTTP") && getenv("HYDRA_PROXY"))
        bail("Found HYDRA_PROXY_HTTP *and* HYDRA_PROXY environment variables - you can use only ONE for the service http-head/http-get!");
      if (getenv("HYDRA_PROXY_HTTP")) {
        printf("[INFO] Using HTTP Proxy: %s\n", getenv("HYDRA_PROXY_HTTP"));
        use_proxy = 1;
      }

      if (strstr(hydra_options.miscptr, "\\:") != NULL) {
        fprintf(stderr, "[INFORMATION] escape sequence \\: detected in module option, no parameter verification is performed.\n");
      } else {
        sprintf(bufferurl, "%.1000s", hydra_options.miscptr);
        url = strtok(bufferurl, ":");
        variables = strtok(NULL, ":");
        cond = strtok(NULL, ":");
        optional1 = strtok(NULL, "\n");
        if ((variables == NULL) || (strstr(variables, "^USER^") == NULL && strstr(variables, "^PASS^") == NULL)) {
          fprintf(stderr, "[ERROR] the variables argument needs at least the strings ^USER^ or ^PASS^: %s\n", variables);
          exit(-1);
        }
        if ((url == NULL) || (cond == NULL)) {
          fprintf(stderr, "[ERROR] Wrong syntax, requires three arguments separated by a colon which may not be null: %s\n", bufferurl);
          exit(-1);
        }
        while ((optional1 = strtok(NULL, ":")) != NULL) {
          if (optional1[1] != '=' && optional1[1] != ':' && optional1[1] != 0) {
            fprintf(stderr, "[ERROR] Wrong syntax of optional argument: %s\n", optional1);
            exit(-1);
          }
          switch (optional1[0]) {
          case 'C':            // fall through
          case 'c':
            if (optional1[1] != '=' || optional1[2] != '/') {
              fprintf(stderr, "[ERROR] Wrong syntax of parameter C, must look like 'C=/url/of/page', not http:// etc.: %s\n", optional1);
              exit(-1);
            }
            break;
          case 'H':            // fall through
          case 'h':
            if (optional1[1] != '=' || strtok(NULL, ":") == NULL) {
              fprintf(stderr, "[ERROR] Wrong syntax of parameter H, must look like 'H=X-My-Header: MyValue', no http:// : %s\n", optional1);
              exit(-1);
            }
            break;
          default:
            fprintf(stderr, "[ERROR] Unknown optional argument: %s", optional1);
          }
        }
      }
    }

    if (strcmp(hydra_options.service, "xmpp") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "irc") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "rdp") == 0) {
      if (hydra_options.tasks > 4)
        fprintf(stderr,
                "[WARNING] rdp servers often don't like many connections, use -t 1 or -t 4 to reduce the number of parallel connections and -W 1 or -W 3 to wait between connection to allow the server to recover\n");
      //if (hydra_options.tasks > 4) {
      //  fprintf(stderr, "[INFO] Reduced number of tasks to 4 (rdp does not like many parallel connections)\n");
      //  hydra_options.tasks = 4;
      //}
      //if (conwait == 0)
      //  hydra_options.conwait = conwait = 1;
      i = 1;
    }
    // ADD NEW SERVICES HERE 

    if (i == 0) {
      fprintf(stderr, "[ERROR] Unknown service: %s\n", hydra_options.service);
      exit(-1);
    }
    if (port < 1 || port > 65535) {
      if ((port = hydra_lookup_port(hydra_options.service)) < 1) {
        fprintf(stderr, "[ERROR] No valid port set or no default port available. Use the -s Option.\n");
        exit(-1);
      }
      hydra_options.port = port;
    }

    if (hydra_options.ssl == 0 && hydra_options.port == 443)
      fprintf(stderr,
              "[WARNING] you specified port 443 for attacking a http service, however did not specify the -S ssl switch nor used https-..., therefore using plain HTTP\n");

    if (hydra_options.loop_mode && hydra_options.colonfile != NULL)
      bail("The loop mode option (-u) works with all modes - except colon files (-C)\n");
    if (strncmp(hydra_options.service, "http-", strlen("http-")) != 0 && strcmp(hydra_options.service, "http-head") != 0 && getenv("HYDRA_PROXY_HTTP") != NULL)
      fprintf(stderr, "[WARNING] the HYDRA_PROXY_HTTP environment variable works only with the http-head/http-get module, ignored...\n");
    if (i == 2) {
      if (hydra_options.colonfile != NULL
          || ((hydra_options.login != NULL || hydra_options.loginfile != NULL) && (hydra_options.pass != NULL || hydra_options.passfile != NULL || hydra_options.bfg > 0)))
        bail
          ("The redis, cisco, oracle-listener, s7-300, snmp and vnc modules are only using the -p or -P option, not login (-l, -L) or colon file (-C).\nUse the telnet module for cisco using \"Username:\" authentication.\n");
      if ((hydra_options.login != NULL || hydra_options.loginfile != NULL) && (hydra_options.pass == NULL || hydra_options.passfile == NULL)) {
        hydra_options.pass = hydra_options.login;
        hydra_options.passfile = hydra_options.loginfile;
      }
      hydra_options.login = empty_login;
      hydra_options.loginfile = NULL;
    }
    if (i == 3) {
      if (hydra_options.colonfile != NULL || hydra_options.bfg > 0
          || ((hydra_options.login != NULL || hydra_options.loginfile != NULL) && (hydra_options.pass != NULL || hydra_options.passfile != NULL)))
        bail("The rsh, oracle-sid login is neither using the -p, -P or -x options nor colon file (-C)\n");
      if ((hydra_options.login == NULL || hydra_options.loginfile == NULL) && (hydra_options.pass != NULL || hydra_options.passfile != NULL)) {
        hydra_options.login = hydra_options.pass;
        hydra_options.loginfile = hydra_options.passfile;
      }
      hydra_options.pass = empty_login;
      hydra_options.passfile = NULL;
    }
    if (i == 3 && hydra_options.login == NULL && hydra_options.loginfile == NULL)
      bail("I need at least either the -l or -L option to know the login");
    if (i == 2 && hydra_options.pass == NULL && hydra_options.passfile == NULL && hydra_options.bfg == 0)
      bail("I need at least either the -p, -P or -x option to have a password to try");
    if (i == 1 && hydra_options.login == NULL && hydra_options.loginfile == NULL && hydra_options.colonfile == NULL)
      bail("I need at least either the -l, -L or -C option to know the login");
    if (hydra_options.colonfile != NULL && ((hydra_options.bfg != 0 || hydra_options.login != NULL || hydra_options.loginfile != NULL)
                                            || (hydra_options.pass != NULL && hydra_options.passfile != NULL)))
      bail("The -C option is standalone, don't use it with -l/L, -p/P or -x!");
    if ((hydra_options.bfg)
        && ((hydra_options.pass != NULL) || (hydra_options.passfile != NULL)
            || (hydra_options.colonfile != NULL)))
      bail("The -x (password bruteforce generation option) doesn't work with -p/P, -C or -e!\n");
    if (hydra_options.try_password_reverse_login == 0 && hydra_options.try_password_same_as_login == 0 && hydra_options.try_null_password == 0
        && (i != 3 && (hydra_options.pass == NULL && hydra_options.passfile == NULL && hydra_options.colonfile == NULL)) && hydra_options.bfg == 0) {
      // test if the service is smtp-enum as it could be used either with a login+pass or only a login 
      if (strstr(hydra_options.service, "smtp-enum") != NULL)
        hydra_options.pass = empty_login;
      else
        bail("I need at least the -e, -p, -P or -x option to have some passwords!");
    }
    if (hydra_options.tasks < 1 || hydra_options.tasks > MAXTASKS) {
      fprintf(stderr, "[ERROR] Option -t needs to be a number between 1 and %d\n", MAXTASKS);
      exit(-1);
    }
    if (hydra_options.max_use > MAXTASKS) {
      fprintf(stderr, "[WARNING] reducing maximum tasks to MAXTASKS (%d)\n", MAXTASKS);
      hydra_options.max_use = MAXTASKS;
    }

    if (hydra_options.colonfile == NULL) {
      if (hydra_options.loginfile != NULL) {
        if ((lfp = fopen(hydra_options.loginfile, "r")) == NULL) {
          fprintf(stderr, "[ERROR] File for logins not found: %s", hydra_options.loginfile);
          exit(-1);
        }
        hydra_brains.countlogin = countlines(lfp, 0);
        hydra_brains.sizelogin = size_of_data;
        if (hydra_brains.countlogin == 0) {
          fprintf(stderr, "[ERROR] File for logins is empty: %s", hydra_options.loginfile);
          exit(-1);
        }
        if (hydra_brains.countlogin > MAX_LINES) {
          fprintf(stderr, "[ERROR] Maximum number of logins is %d, this file has %lu entries.\n", MAX_LINES, hydra_brains.countlogin);
          exit(-1);
        }
        if (hydra_brains.sizelogin > MAX_BYTES) {
          fprintf(stderr, "[ERROR] Maximum size of the login file is %d, this file has %lu bytes.\n", MAX_BYTES, (unsigned long int) hydra_brains.sizelogin);
          exit(-1);
        }
        login_ptr = malloc(hydra_brains.sizelogin + hydra_brains.countlogin + 8);
        if (login_ptr == NULL)
          bail("Could not allocate enough memory for login file data");
        memset(login_ptr, 0, hydra_brains.sizelogin + hydra_brains.countlogin + 8);
        fill_mem(login_ptr, lfp, 0);
      } else {
        login_ptr = hydra_options.login;
        hydra_brains.sizelogin = strlen(hydra_options.login) + 1;
        hydra_brains.countlogin = 1;
      }
      if (hydra_options.passfile != NULL) {
        if ((pfp = fopen(hydra_options.passfile, "r")) == NULL) {
          fprintf(stderr, "[ERROR] File for passwords not found: %s", hydra_options.passfile);
          exit(-1);
        }
        hydra_brains.countpass = countlines(pfp, 0);
        hydra_brains.sizepass = size_of_data;
        if (hydra_brains.countpass == 0) {
          fprintf(stderr, "[ERROR] File for passwords is empty: %s", hydra_options.passfile);
          exit(-1);
        }
        if (hydra_brains.countpass > MAX_LINES) {
          fprintf(stderr, "[ERROR] Maximum number of passwords is %d, this file has %lu entries.\n", MAX_LINES, hydra_brains.countpass);
          exit(-1);
        }
        if (hydra_brains.sizepass > MAX_BYTES) {
          fprintf(stderr, "[ERROR] Maximum size of the password file is %d, this file has %lu bytes.\n", MAX_BYTES, (unsigned long int) hydra_brains.sizepass);
          exit(-1);
        }
        pass_ptr = malloc(hydra_brains.sizepass + hydra_brains.countpass + 8);
        if (pass_ptr == NULL)
          bail("Could not allocate enough memory for password file data");
        memset(pass_ptr, 0, hydra_brains.sizepass + hydra_brains.countpass + 8);
        fill_mem(pass_ptr, pfp, 0);
      } else {
        if (hydra_options.pass != NULL) {
          pass_ptr = hydra_options.pass;
          hydra_brains.countpass = 1;
          hydra_brains.sizepass = strlen(hydra_options.pass) + 1;
        } else {
          if (hydra_options.bfg) {
#ifdef HAVE_MATH_H
            if (bf_init(bf_options.arg))
              exit(-1);         // error description is handled by bf_init
            pass_ptr = bf_next();
            hydra_brains.countpass += bf_get_pcount();
            hydra_brains.sizepass += BF_BUFLEN;
#else
            sleep(1);
#endif
          } else {
            pass_ptr = hydra_options.pass = empty_login;
            hydra_brains.countpass = 0;
            hydra_brains.sizepass = 1;
          }
        }
      }
    } else {
      if ((cfp = fopen(hydra_options.colonfile, "r")) == NULL) {
        fprintf(stderr, "[ERROR] File for colon files (login:pass) not found: %s", hydra_options.colonfile);
        exit(-1);
      }
      hydra_brains.countlogin = countlines(cfp, 1);
      hydra_brains.sizelogin = size_of_data;
      if (hydra_brains.countlogin == 0) {
        fprintf(stderr, "[ERROR] File for colon files (login:pass) is empty: %s", hydra_options.colonfile);
        exit(-1);
      }
      if (hydra_brains.countlogin > MAX_LINES / 2) {
        fprintf(stderr, "[ERROR] Maximum number of colon file entries is %d, this file has %lu entries.\n", MAX_LINES / 2, hydra_brains.countlogin);
        exit(-1);
      }
      if (hydra_brains.sizelogin > MAX_BYTES / 2) {
        fprintf(stderr, "[ERROR] Maximum size of the colon file is %d, this file has %lu bytes.\n", MAX_BYTES / 2, (unsigned long int) hydra_brains.sizelogin);
        exit(-1);
      }
      csv_ptr = malloc(hydra_brains.sizelogin + 2 * hydra_brains.countlogin + 8);
      if (csv_ptr == NULL)
        bail("Could not allocate enough memory for colon file data");
      memset(csv_ptr, 0, hydra_brains.sizelogin + 2 * hydra_brains.countlogin + 8);
      fill_mem(csv_ptr, cfp, 1);
//printf("count: %d, size: %d\n", hydra_brains.countlogin, hydra_brains.sizelogin);
//hydra_dump_data(csv_ptr, hydra_brains.sizelogin + hydra_brains.countlogin + 8, "colon data");
      hydra_brains.countpass = 1;
      pass_ptr = login_ptr = csv_ptr;
      while (*pass_ptr != 0)
        pass_ptr++;
      pass_ptr++;
    }

    hydra_brains.countpass += hydra_options.try_password_reverse_login + hydra_options.try_password_same_as_login + hydra_options.try_null_password;
    if ((memcheck = malloc(102400)) == NULL) {
      fprintf(stderr, "[ERROR] your wordlist is too large, not enough memory!\n");
      exit(-1);
    }
    free(memcheck);
    if ((rfp = fopen(RESTOREFILE, "r")) != NULL) {
      fprintf(stderr, "[WARNING] Restorefile (%s) from a previous session found, to prevent overwriting, you have 10 seconds to abort...\n", RESTOREFILE);
      sleep(10);
      fclose(rfp);
    }

    if (hydra_options.infile_ptr != NULL) {
      if ((ifp = fopen(hydra_options.infile_ptr, "r")) == NULL) {
        fprintf(stderr, "[ERROR] File for targets not found: %s", hydra_options.infile_ptr);
        exit(-1);
      }
      hydra_brains.targets = countservers = countinfile = countlines(ifp, 0);
      if (countinfile == 0) {
        fprintf(stderr, "[ERROR] File for targets is empty: %s", hydra_options.infile_ptr);
        exit(-1);
      }
// if (countinfile > 60) fprintf(stderr, "[WARNING] the -M option is not working correctly at the moment for target lists > 60!\n");
      hydra_targets = malloc(sizeof(hydra_targets) * (countservers + 2) + 8);
      if (hydra_targets == NULL)
        bail("Could not allocate enough memory for target data");
      sizeinfile = size_of_data;
      if (countinfile > MAX_LINES / 1000) {
        fprintf(stderr, "[ERROR] Maximum number of target file entries is %d, this file has %d entries.\n", MAX_LINES / 1000, (int) countinfile);
        exit(-1);
      }
      if (sizeinfile > MAX_BYTES / 1000) {
        fprintf(stderr, "[ERROR] Maximum size of the server file is %d, this file has %d bytes.\n", MAX_BYTES / 1000, (int) sizeinfile);
        exit(-1);
      }
      if ((servers_ptr = malloc(sizeinfile + countservers + 8)) == NULL)
        bail("Could not allocate enough memory for target file data");
      memset(servers_ptr, 0, sizeinfile + countservers + 8);
      fill_mem(servers_ptr, ifp, 0);
      sizeservers = sizeinfile;
      tmpptr = servers_ptr;
      for (i = 0; i < countinfile; i++) {
        hydra_targets[i] = malloc(sizeof(hydra_target));
        memset(hydra_targets[i], 0, sizeof(hydra_target));
        if (*tmpptr == '[') {
          tmpptr++;
          hydra_targets[i]->target = tmpptr;
          if ((tmpptr2 = index(tmpptr, ']')) != NULL) {
            *tmpptr2++ = 0;
            tmpptr = tmpptr2;
          }
        } else
          hydra_targets[i]->target = tmpptr;
        if ((tmpptr2 = index(hydra_targets[i]->target, ':')) != NULL) {
          *tmpptr2++ = 0;
          tmpptr = tmpptr2;
          hydra_targets[i]->port = atoi(tmpptr2);
          if (hydra_targets[i]->port < 1 || hydra_targets[i]->port > 65535)
            hydra_targets[i]->port = 0;
        }
        if (hydra_targets[i]->port == 0)
          hydra_targets[i]->port = hydra_options.port;
        while (*tmpptr != 0)
          tmpptr++;
        tmpptr++;
      }
    } else if (index(hydra_options.server, '/') != NULL) {
      /* CIDR notation on command line, e.g. 192.168.0.0/24 */
      unsigned int four_from, four_to, addr_cur, addr_cur2, k, l;
      in_addr_t addr4;
      struct sockaddr_in target;

      hydra_options.cidr = 1;
      do_retry = 0;
      if ((tmpptr = malloc(strlen(hydra_options.server) + 1)) == NULL) {
        fprintf(stderr, "Error: can not allocate memory\n");
        exit(-1);
      }
      strcpy(tmpptr, hydra_options.server);
      tmpptr2 = index(tmpptr, '/');
      *tmpptr2++ = 0;
      if ((k = atoi(tmpptr2)) < 16 || k > 31) {
        fprintf(stderr, "Error: network size may only be between /16 and /31: %s\n", hydra_options.server);
        exit(-1);
      }
      if ((addr4 = htonl(inet_addr(tmpptr))) == 0xffffffff) {
        fprintf(stderr, "Error: option is not a valid IPv4 address: %s\n", tmpptr);
        exit(-1);
      }
      free(tmpptr);
      l = 1 << (32 - k);
      l--;
      four_to = (addr4 | l);
      l = 0xffffffff - l;
      four_from = (addr4 & l);
      l = 1 << (32 - k);
      hydra_brains.targets = countservers = l;
      hydra_targets = malloc(sizeof(hydra_targets) * (l + 2) + 8);
      if (hydra_targets == NULL)
        bail("Could not allocate enough memory for target data");
      i = 0;
      addr_cur = four_from;
      while (addr_cur <= four_to && i < l) {
        hydra_targets[i] = malloc(sizeof(hydra_target));
        memset(hydra_targets[i], 0, sizeof(hydra_target));
        addr_cur2 = htonl(addr_cur);
        memcpy(&target.sin_addr.s_addr, (char *) &addr_cur2, 4);
        hydra_targets[i]->target = strdup(inet_ntoa((struct in_addr) target.sin_addr));
        hydra_targets[i]->port = hydra_options.port;
        addr_cur++;
        i++;
      }
      if (verbose)
        printf("[VERBOSE] CIDR attack from %s to %s\n", hydra_targets[0]->target, hydra_targets[l - 1]->target);
      printf("[WARNING] The CIDR attack mode is still beta. Please report issues.\n");
    } else {                    // standard: single target on command line
      countservers = hydra_brains.targets = 1;
      hydra_targets = malloc(sizeof(int) * 4);
      hydra_targets[0] = malloc(sizeof(hydra_target));
      memset(hydra_targets[0], 0, sizeof(hydra_target));
      hydra_targets[0]->target = servers_ptr = hydra_options.server;
      hydra_targets[0]->port = hydra_options.port;
      sizeservers = strlen(hydra_options.server) + 1;
    }
    for (i = 0; i < hydra_brains.targets; i++) {
      hydra_targets[i]->login_ptr = login_ptr;
      hydra_targets[i]->pass_ptr = pass_ptr;
      if (hydra_options.loop_mode) {
        if (hydra_options.try_password_same_as_login)
          hydra_targets[i]->pass_state = 0;
        else if (hydra_options.try_null_password) {
          hydra_targets[i]->pass_ptr = empty_login;
          hydra_targets[i]->pass_state = 1;
        } else if (hydra_options.try_password_reverse_login)
          hydra_targets[i]->pass_state = 2;
        else
          hydra_targets[i]->pass_state = 3;
      }
    }
  }                             // END OF restore == 0 

  if (getenv("HYDRA_PROXY") && use_proxy == 0) {
    printf("[INFO] Using Connect Proxy: %s\n", getenv("HYDRA_PROXY"));
    use_proxy = 2;
  }
  if (use_proxy == 1)
    proxy_string = getenv("HYDRA_PROXY_HTTP");
  if (use_proxy == 2)
    proxy_string = getenv("HYDRA_PROXY");
  if (proxy_string != NULL && proxy_string[0] != 0) {
    if (strstr(proxy_string, "//") != NULL) {
      char *dslash = strstr(proxy_string, "://");

      if (dslash) {
        proxy_string[dslash - proxy_string] = 0;
        strncpy(proxy_string_type, proxy_string, sizeof(proxy_string_type) - 1);
        proxy_string_type[sizeof(proxy_string_type) - 1] = 0;
      }

      proxy_string = dslash;
      proxy_string += 3;
    }
    if (proxy_string[strlen(proxy_string) - 1] == '/')
      proxy_string[strlen(proxy_string) - 1] = 0;
    if ((tmpptr = index(proxy_string, ':')) == NULL)
      use_proxy = 0;
    else {
      *tmpptr = 0;
      tmpptr++;
      memset(&hints, 0, sizeof hints);
      if ((device = index(proxy_string, '%')) != NULL)
        *device++ = 0;
      if (getaddrinfo(proxy_string, NULL, &hints, &res) != 0) {
        fprintf(stderr, "[ERROR] could not resolve proxy address: %s\n", proxy_string);
        exit(-1);
      } else {
        for (p = res; p != NULL; p = p->ai_next) {
#ifdef AF_INET6
          if (p->ai_family == AF_INET6) {
            if (ipv6 == NULL)
              ipv6 = (struct sockaddr_in6 *) p->ai_addr;
          } else
#endif
          if (p->ai_family == AF_INET) {
            if (ipv4 == NULL)
              ipv4 = (struct sockaddr_in *) p->ai_addr;
          }
        }
        freeaddrinfo(res);
#ifdef AF_INET6
        if (ipv6 != NULL && (ipv4 == NULL || prefer_ipv6)) {
          proxy_string_ip[0] = 16;
          memcpy(proxy_string_ip + 1, (char *) &ipv6->sin6_addr, 16);
          if (device != NULL && strlen(device) <= 16)
            strcpy(proxy_string_ip + 17, device);
          if (memcmp(proxy_string_ip + 1, fe80, 2) == 0) {
            if (device == NULL) {
              fprintf(stderr, "[ERROR] The proxy address is a link local address, link local addresses require the interface being defined like this: fe80::1%%eth0\n");
              exit(-1);
            }
          }
        } else
#endif
        if (ipv4 != NULL) {
          proxy_string_ip[0] = 4;
          memcpy(proxy_string_ip + 1, (char *) &ipv4->sin_addr, 4);
        } else {
          fprintf(stderr, "[ERROR] Could not resolve proxy address: %s\n", proxy_string);
          exit(-1);
        }
      }
      proxy_string_port = atoi(tmpptr);
    }
    if (use_proxy == 0)
      fprintf(stderr, "[WARNING] invalid proxy definition. Syntax: \"HYDRA_PROXY=[connect|socks[4|5]]://1.2.3.4:3128/\".\n");
  } else
    use_proxy = 0;
  if (use_proxy > 0 && (tmpptr = getenv("HYDRA_PROXY_AUTH")) != NULL && tmpptr[0] != 0) {
    if (index(tmpptr, ':') == NULL) {
      fprintf(stderr, "[WARNING] invalid proxy authentication. Syntax: \"login:password\". Ignoring ...\n");
    } else {
      proxy_authentication = malloc(strlen(tmpptr) * 2 + 50);
      strcpy(proxy_authentication, tmpptr);
      if (hydra_strcasestr(proxy_string_type, "socks") == NULL)
        hydra_tobase64((unsigned char *) proxy_authentication, strlen(proxy_authentication), strlen(tmpptr) * 2 + 8);
    }
  }

  if (hydra_options.restore == 0) {
    if ((strcmp(hydra_options.service, "rsh") == 0) || (strcmp(hydra_options.service, "oracle-sid") == 0))
      math2 = hydra_brains.countlogin;
    else
      math2 = hydra_brains.countlogin * hydra_brains.countpass;

#ifdef HAVE_MATH_H
    if (hydra_options.bfg) {
      math2 = hydra_brains.countlogin * bf_get_pcount();
    }
#endif

    hydra_brains.todo = math2;
    math2 = math2 * hydra_brains.targets;
    hydra_brains.todo_all = math2;
    if (hydra_brains.todo_all == 0)
      bail("No login/password combination given!");
    if (hydra_brains.todo < hydra_options.tasks) {
      if (verbose && hydra_options.tasks != TASKS)
        printf("[VERBOSE] More tasks defined than login/pass pairs exist. Tasks reduced to %lu\n", hydra_brains.todo);
      hydra_options.tasks = hydra_brains.todo;
    }
  }
  if (hydra_options.max_use == MAXTASKS) { // only if it was not set via -T
    if (hydra_options.max_use < hydra_brains.targets * hydra_options.tasks)
      hydra_options.max_use = hydra_brains.targets * hydra_options.tasks;
    if (hydra_options.max_use > MAXTASKS)
      hydra_options.max_use = MAXTASKS;
  }
  if ((hydra_options.tasks == TASKS || hydra_options.tasks <= 8) && hydra_options.max_use < hydra_brains.targets * hydra_options.tasks) {
    if ((hydra_options.tasks = hydra_options.max_use / hydra_brains.targets) == 0)
      hydra_options.tasks = 1;
    //fprintf(stderr, "[WARNING] More tasks defined per server than allowed for maximal connections. Tasks per server reduced to %d.\n", hydra_options.tasks);
  } else {
    if (hydra_options.tasks > MAXTASKS) {
      //fprintf(stderr, "[WARNING] reducing tasks to MAXTASKS (%d)\n", MAXTASKS);
      hydra_options.tasks = MAXTASKS;
    }
  }
//  hydra_options.max_use = hydra_brains.targets * hydra_options.tasks;
//  if (hydra_options.max_use > MAXTASKS)
//    hydra_options.max_use = MAXTASKS;
  math2 = (hydra_brains.todo / hydra_options.tasks);
  if (hydra_brains.todo % hydra_options.tasks)
    math2++;
  math2 = (math2 * hydra_brains.targets) / hydra_options.max_use;
  // set options (bits!) 
  options = 0;
  if (hydra_options.ssl)
    options = options | OPTION_SSL;
  if (hydra_options.colonfile != NULL)
    printf("[DATA] max %d task%s per %d server%s, overall %d tasks, %lu login tr%s, ~%lu tr%s per task\n", hydra_options.tasks, hydra_options.tasks == 1 ? "" : "s",
           hydra_brains.targets, hydra_brains.targets == 1 ? "" : "s", hydra_options.max_use, hydra_brains.todo, hydra_brains.todo == 1 ? "y" : "ies", math2,
           math2 == 1 ? "y" : "ies");
  else
    printf("[DATA] max %d task%s per %d server%s, overall %d tasks, %lu login tr%s (l:%lu/p:%lu), ~%lu tr%s per task\n", hydra_options.tasks, hydra_options.tasks == 1 ? "" : "s",
           hydra_brains.targets, hydra_brains.targets == 1 ? "" : "s", hydra_options.max_use, hydra_brains.todo, hydra_brains.todo == 1 ? "y" : "ies",
           (unsigned long int) hydra_brains.countlogin, (unsigned long int) hydra_brains.countpass, math2, math2 == 1 ? "y" : "ies");

  printf("[DATA] attacking service %s on port %d%s\n", hydra_options.service, port,  hydra_options.ssl == 1 ? " with SSL" : "");

  if (hydra_options.outfile_ptr != NULL) {
    if ((hydra_brains.ofp = fopen(hydra_options.outfile_ptr, "a+")) == NULL) {
      perror("[ERROR] Error creating outputfile");
      exit(-1);
    }
    fprintf(hydra_brains.ofp, "# %s %s run at %s on %s %s (%s", PROGRAM, VERSION, hydra_build_time(),
            hydra_options.server == NULL ? hydra_options.infile_ptr : hydra_options.server, hydra_options.service, prg);
    for (i = 1; i < argc; i++)
      fprintf(hydra_brains.ofp, " %s", argv[i]);
    fprintf(hydra_brains.ofp, ")\n");
  }
  // we have to flush all writeable buffered file pointers before forking 
  // set appropriate signals for mother 
  signal(SIGCHLD, killed_childs);
  if (debug == 0)
    signal(SIGTERM, kill_children);
  if (debug == 0) {
#ifdef SIGBUS
    signal(SIGBUS, kill_children);
#endif
    signal(SIGSEGV, kill_children);
  }
  signal(SIGHUP, kill_children);
  signal(SIGINT, kill_children);
  signal(SIGPIPE, SIG_IGN);
  if (verbose)
    printf("[VERBOSE] Resolving addresses ... ");
  if (debug)
    printf("\n");
  for (i = 0; i < hydra_brains.targets; i++) {
    if (debug)
      printf("[DEBUG] resolving %s\n", hydra_targets[i]->target);
    memset(&hints, 0, sizeof(hints));
    ipv4 = NULL;
#ifdef AF_INET6
    ipv6 = NULL;
    if ((device = index(hydra_targets[i]->target, '%')) != NULL)
      *device++ = 0;
#endif
    if (getaddrinfo(hydra_targets[i]->target, NULL, &hints, &res) != 0) {
      if (use_proxy == 0) {
        if (verbose)
          printf("[failed for %s] ", hydra_targets[i]->target);
        else
          fprintf(stderr, "[ERROR] could not resolve address: %s\n", hydra_targets[i]->target);
        hydra_targets[i]->done = 3;
        hydra_brains.finished++;
      }
    } else {
      for (p = res; p != NULL; p = p->ai_next) {
#ifdef AF_INET6
        if (p->ai_family == AF_INET6) {
          if (ipv6 == NULL)
            ipv6 = (struct sockaddr_in6 *) p->ai_addr;
        } else
#endif
        if (p->ai_family == AF_INET) {
          if (ipv4 == NULL)
            ipv4 = (struct sockaddr_in *) p->ai_addr;
        }
      }
#ifdef AF_INET6
      if (ipv6 != NULL && (ipv4 == NULL || prefer_ipv6)) {
        // IPV6 FIXME
        if ((strcmp(hydra_options.service, "socks5") == 0) || (strcmp(hydra_options.service, "sip") == 0)) {
          fprintf(stderr, "[ERROR] Target %s resolves to an IPv6 address, however module %s does not support this. Maybe try \"-4\" option. Sending in patches helps.\n",
                  hydra_targets[i]->target, hydra_options.service);
          hydra_targets[i]->done = 3;
          hydra_brains.finished++;
        } else {
          hydra_targets[i]->ip[0] = 16;
          memcpy(&hydra_targets[i]->ip[1], (char *) &ipv6->sin6_addr, 16);
          if (device != NULL && strlen(device) <= 16)
            strcpy(&hydra_targets[i]->ip[17], device);
          if (memcmp(&hydra_targets[i]->ip[17], fe80, 2) == 0) {
            if (device == NULL) {
              fprintf(stderr, "[ERROR] The target %s address is a link local address, link local addresses require the interface being defined like this: fe80::1%%eth0\n",
                      hydra_targets[i]->target);
              exit(-1);
            }
          }
        }
      } else
#endif
      if (ipv4 != NULL) {
        hydra_targets[i]->ip[0] = 4;
        memcpy(&hydra_targets[i]->ip[1], (char *) &ipv4->sin_addr, 4);
      } else {
        if (verbose)
          printf("[failed for %s] ", hydra_targets[i]->target);
        else
          fprintf(stderr, "[ERROR] Could not resolve proxy address: %s\n", hydra_targets[i]->target);
        hydra_targets[i]->done = 3;
        hydra_brains.finished++;
      }
      freeaddrinfo(res);
    }
  }
  if (verbose)
    printf("done\n");
  if (hydra_brains.targets == 0)
    bail("No server to scan!");

#ifndef SO_BINDTODEVICE
  if (device != NULL) {
    fprintf(stderr, "[ERROR] your operating system does not support SO_BINDTODEVICE or IP_FORCE_OUT_IFP, dunno how to bind the IPv6 address to the interface %s!\n", device);
  }
#endif

  if (hydra_options.restore == 0) {
    hydra_heads = malloc(sizeof(hydra_heads) * hydra_options.max_use);
    target_no = 0;
    for (i = 0; i < hydra_options.max_use; i++) {
      hydra_heads[i] = malloc(sizeof(hydra_head));
      memset(hydra_heads[i], 0, sizeof(hydra_head));
    }
  }
  // here we call the init function of the relevant service module
  // should we do the init centrally or should each child do that?
  // that depends largely on the number of targets and maximum tasks
//  if (hydra_brains.targets == 1 || (hydra_brains.targets < 4 && hydra_options.tasks / hydra_brains.targets > 4 && hydra_brains.todo > 15))
  for (i = 0; i < hydra_brains.targets; i++)
    hydra_service_init(i);

  starttime = elapsed_status = elapsed_restore = time(NULL);
  fflush(stdout);
  fflush(stderr);
  fflush(hydra_brains.ofp);

  hydra_debug(0, "attack");
  process_restore = 1;

  // this is the big function which starts the attacking children, feeds login/password pairs, etc.! 
  while (exit_condition == 0) {
    FD_ZERO(&fdreadheads);
    for (head_no = 0, max_fd = 1; head_no < hydra_options.max_use; head_no++) {
      if (hydra_heads[head_no]->active > 0) {
        FD_SET(hydra_heads[head_no]->sp[0], &fdreadheads);
        if (max_fd < hydra_heads[head_no]->sp[0])
          max_fd = hydra_heads[head_no]->sp[0];
      }
    }
    my_select(max_fd + 1, &fdreadheads, NULL, NULL, 0, 200000);
    tmp_time = time(NULL);

    for (head_no = 0; head_no < hydra_options.max_use; head_no++) {
      if (debug && hydra_heads[head_no]->active != -1) printf("[DEBUG] head_no[%d] to target_no %d active %d\n", head_no, hydra_heads[head_no]->target_no, hydra_heads[head_no]->active);
      switch (hydra_heads[head_no]->active) {
      case -1:
        // disabled head, ignored
        break;
      case 0:
        if (hydra_heads[head_no]->redo) {
          hydra_spawn_head(head_no, hydra_heads[head_no]->target_no);
        } else {
          if (hydra_brains.targets > hydra_brains.finished)
            hydra_heads[head_no]->target_no = hydra_select_target();
          else
            hydra_heads[head_no]->target_no = -1;
          if (debug)
            printf("[DEBUG] child %d got target %d selected\n", head_no, hydra_heads[head_no]->target_no);
          if (hydra_heads[head_no]->target_no < 0) {
            if (debug) printf("[DEBUG] hydra_select_target() reports no more targets left\n");
            hydra_kill_head(head_no, 0, 3);
          } else
            hydra_spawn_head(head_no, hydra_heads[head_no]->target_no); // target_no is ignored if head->redo == 1
        }
        break;
      case 1:
        if (FD_ISSET(hydra_heads[head_no]->sp[0], &fdreadheads)) {
          readres = read_safe(hydra_heads[head_no]->sp[0], &rc, 1);
          if (readres > 0) {
            FD_CLR(hydra_heads[head_no]->sp[0], &fdreadheads);
            hydra_heads[head_no]->last_seen = tmp_time;
            if (debug)
              printf("[DEBUG] head_no[%d] read %c\n", head_no, rc);
            switch (rc) {
              // Valid Results:
              //  n - mother says to itself that child requests next login/password pair
              //  N - child requests next login/password pair
              //  Q - child reports that it is quitting
              //  C - child reports connect error (and is quitting)
              //  E - child reports protocol error (and is quitting)
              //  f - child reports that the username does not exist
              //  F - child reports that it found a valid login/password pair
              //        and requests next pair. Sends login/pw pair with next msg!
            case 'N':          // head wants next pair
              hydra_targets[hydra_heads[head_no]->target_no]->ok = 1;
              if (hydra_targets[hydra_heads[head_no]->target_no]->fail_count > 0)
                hydra_targets[hydra_heads[head_no]->target_no]->fail_count--;
              // no break here 
            case 'n':          // mother sends this to itself initially
              loop_cnt = 0;
              if (hydra_send_next_pair(hydra_heads[head_no]->target_no, head_no) == -1)
                hydra_kill_head(head_no, 1, 0);
              break;

            case 'F':          // valid password found
              hydra_brains.found++;
              if (colored_output) {
                if (hydra_heads[head_no]->current_login_ptr == NULL || strlen(hydra_heads[head_no]->current_login_ptr) == 0) {
                  if (hydra_heads[head_no]->current_pass_ptr == NULL || strlen(hydra_heads[head_no]->current_pass_ptr) == 0)
                    printf("[\e[1;32m%d\e[0m][\e[1;32m%s\e[0m] host: \e[1;32m%s\e[0m\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target);
                  else
                    printf("[\e[1;32m%d\e[0m][\e[1;32m%s\e[0m] host: \e[1;32m%s\e[0m   password: \e[1;32m%s\e[0m\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_pass_ptr);
                } else if (hydra_heads[head_no]->current_pass_ptr == NULL || strlen(hydra_heads[head_no]->current_pass_ptr) == 0) {
                  printf("[\e[1;32m%d\e[0m][\e[1;32m%s\e[0m] host: \e[1;32m%s\e[0m   login: \e[1;32m%s\e[0m\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_login_ptr);
                } else
                  printf("[\e[1;32m%d\e[0m][\e[1;32m%s\e[0m] host: \e[1;32m%s\e[0m   login: \e[1;32m%s\e[0m   password: \e[1;32m%s\e[0m\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr);
              } else {
                if (hydra_heads[head_no]->current_login_ptr == NULL || strlen(hydra_heads[head_no]->current_login_ptr) == 0) {
                  if (hydra_heads[head_no]->current_pass_ptr == NULL || strlen(hydra_heads[head_no]->current_pass_ptr) == 0)
                    printf("[%d][%s] host: %s\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target);
                  else
                    printf("[%d][%s] host: %s   password: %s\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_pass_ptr);
                } else if (hydra_heads[head_no]->current_pass_ptr == NULL || strlen(hydra_heads[head_no]->current_pass_ptr) == 0) {
                  printf("[%d][%s] host: %s   login: %s\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_login_ptr);
                } else
                  printf("[%d][%s] host: %s   login: %s   password: %s\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr);
              }
              if (hydra_options.outfile_ptr != NULL && hydra_brains.ofp != NULL) {
                if (hydra_heads[head_no]->current_login_ptr == NULL || strlen(hydra_heads[head_no]->current_login_ptr) == 0) {
                  if (hydra_heads[head_no]->current_pass_ptr == NULL || strlen(hydra_heads[head_no]->current_pass_ptr) == 0)
                    fprintf(hydra_brains.ofp, "[%d][%s] host: %s\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target);
                  else
                    fprintf(hydra_brains.ofp, "[%d][%s] host: %s   password: %s\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_pass_ptr);
                } else if (hydra_heads[head_no]->current_pass_ptr == NULL || strlen(hydra_heads[head_no]->current_pass_ptr) == 0) {
                  fprintf(hydra_brains.ofp, "[%d][%s] host: %s   login: %s\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_login_ptr);
                } else
                  fprintf(hydra_brains.ofp, "[%d][%s] host: %s   login: %s   password: %s\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr);
              }
              if (hydra_options.exit_found) {   // option set says quit target after on valid login/pass pair is found 
                if (hydra_targets[hydra_heads[head_no]->target_no]->done == 0) {
                  hydra_targets[hydra_heads[head_no]->target_no]->done = 1;     // mark target as done 
                  hydra_brains.finished++;
                  printf("[STATUS] attack finished for %s (valid pair found)\n", hydra_targets[hydra_heads[head_no]->target_no]->target);
                }
                if (hydra_options.exit_found == 2) {
                  for (j = 0; j < hydra_brains.targets; j++)
                    if (hydra_targets[j]->done == 0) {
                      hydra_targets[j]->done = 1;
                      hydra_brains.finished++;
                    }
                }
                for (j = 0; j < hydra_options.max_use; j++)
                  if (hydra_heads[j]->active >= 0 && (hydra_heads[j]->target_no == target_no || hydra_options.exit_found == 2)) {
                    if (hydra_brains.targets > hydra_brains.finished && hydra_options.exit_found < 2)
                      hydra_kill_head(j, 1, 0);   // kill all heads working on the target 
                    else
                      hydra_kill_head(j, 1, 2);   // kill all heads working on the target 
                }
                continue;
              }
              // fall through
            case 'f':          // username identified as invalid
              hydra_targets[hydra_heads[head_no]->target_no]->ok = 1;
              if (hydra_targets[hydra_heads[head_no]->target_no]->fail_count > 0)
                hydra_targets[hydra_heads[head_no]->target_no]->fail_count--;
              memset(buf, 0, sizeof(buf));
              read_safe(hydra_heads[head_no]->sp[0], buf, MAXBUF);
              hydra_skip_user(hydra_heads[head_no]->target_no, buf);
              fck = write(hydra_heads[head_no]->sp[1], "n", 1); // small hack
              break;

              // we do not make a difference between 'C' and 'E' results - yet 
            case 'E':          // head reports protocol error
            case 'C':          // head reports connect error
              fck = write(hydra_heads[head_no]->sp[0], "Q", 1);
              if (debug) {
                printf("[ATTEMPT-ERROR] target %s - login \"%s\" - pass \"%s\" - child %d - %lu of %lu\n",
                       hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, head_no,
                       hydra_targets[hydra_heads[head_no]->target_no]->sent, hydra_brains.todo);
              }
              hydra_increase_fail_count(hydra_heads[head_no]->target_no, head_no);
              break;

            case 'Q':          // head reports its quitting
              fck = write(hydra_heads[head_no]->sp[0], "Q", 1);
              if (debug)
                printf("[DEBUG] child %d reported it quit\n", head_no);
              hydra_kill_head(head_no, 1, 0);
              break;

            default:
              fprintf(stderr, "[ERROR] child %d sent nonsense data, killing and restarting it!\n", head_no);
              hydra_increase_fail_count(hydra_heads[head_no]->target_no, head_no);
            }
          }
          if (readres == -1) {
            if (verbose)
              fprintf(stderr, "[WARNING] child %d seems to have died, restarting (this only happens if a module is bad) ... \n", head_no);
            hydra_increase_fail_count(hydra_heads[head_no]->target_no, head_no);
          }
        } else {
          if (hydra_heads[head_no]->last_seen + hydra_options.waittime > tmp_time) {
            // check if recover of timed-out head is necessary
            if (tmp_time > waittime + hydra_heads[head_no]->last_seen) {
              if (kill(hydra_heads[head_no]->pid, 0) < 0) {
                if (verbose)
                  fprintf(stderr, "[WARNING] child %d seems to be dead, restarting it ...\n", head_no);
                hydra_increase_fail_count(hydra_heads[head_no]->target_no, head_no);
              }
            }
            // if we do not get to hear anything for a longer time assume its dead
            if (tmp_time > waittime * 2 + hydra_heads[head_no]->last_seen) {
              if (verbose)
                fprintf(stderr, "[WARNING] timeout from child %d, restarting\n", head_no);
              hydra_increase_fail_count(hydra_heads[head_no]->target_no, head_no);
            }
          }
        }
        break;
      default:
        fprintf(stderr, "[ERROR] child %d in unknown state, restarting!\n", head_no);
        hydra_increase_fail_count(hydra_heads[head_no]->target_no, head_no);
      }
    }

    usleep(USLEEP_LOOP);
    (void) wait3(NULL, WNOHANG, NULL);
    // write restore file and report status 
    if (process_restore == 1 && time(NULL) - elapsed_restore > 299) {
      hydra_restore_write(0);
      elapsed_restore = time(NULL);
    }

    if (time(NULL) - elapsed_status > status_print) {
      elapsed_status = time(NULL);
      tmp_time = elapsed_status - starttime;
      if (tmp_time < 1)
        tmp_time = 1;
      tmp_time = hydra_brains.sent / tmp_time;
      if (tmp_time < 1)
        tmp_time = 1;
      if (status_print < 15 * 59)
        status_print = ((status_print + 1) * 2) - 1;
      if (status_print > 299 && (hydra_brains.todo_all - hydra_brains.sent) / tmp_time < 1500)
        status_print = 299;
      if (((hydra_brains.todo_all - hydra_brains.sent) / tmp_time) < 150)
        status_print = 59;
      k = 0;
      for (j = 0; j < hydra_options.max_use; j++)
        if (hydra_heads[j]->active >= 0)
          k++;
      printf("[STATUS] %.2f tries/min, %lu tries in %02lu:%02luh, %lu to do in %02lu:%02luh, %d active\n", (1.0 * hydra_brains.sent) / (((elapsed_status - starttime) * 1.0) / 60),      // tries/min 
             hydra_brains.sent, // tries 
             (long unsigned int) ((elapsed_status - starttime) / 3600), // hours 
             (long unsigned int) (((elapsed_status - starttime) % 3600) / 60),  // minutes 
             hydra_brains.todo_all - hydra_brains.sent <= 0 ? 1 : hydra_brains.todo_all - hydra_brains.sent,    // left todo 
             (long unsigned int) (((double) hydra_brains.todo_all - hydra_brains.sent) / ((double) hydra_brains.sent / (elapsed_status - starttime))
             ) / 3600,          // hours 
             (((long unsigned int) (((double) hydra_brains.todo_all - hydra_brains.sent) / ((double) hydra_brains.sent / (elapsed_status - starttime))
               ) % 3600) / 60) + 1,     // min 
             k);
      hydra_debug(0, "STATUS");
    }

    exit_condition = hydra_check_for_exit_condition();
  }
  process_restore = 0;
  if (debug)
    printf("[DEBUG] while loop left with %d\n", exit_condition);

  j = k = error = 0;
  for (i = 0; i < hydra_brains.targets; i++)
    switch (hydra_targets[i]->done) {
    case 3:
      k++;
      break;
    case 2:
      if (hydra_targets[i]->ok == 0)
        k++;
      else
        error++;
      break;
    case 1:
      break;
    case 0:
      if (hydra_targets[i]->ok == 0)
        k++;
      else
        j++;
      break;
    default:
      error++;
      fprintf(stderr, "[ERROR] illegal target result value (%d=>%d)\n", i, hydra_targets[i]->done);
    }

  if (debug) printf("[DEBUG] killing all remaining childs now that might be stuck\n");
  for (i = 0; i < hydra_options.max_use; i++)
    if (hydra_heads[i]->active > 0 && hydra_heads[i]->pid > 0)
      hydra_kill_head(i, 1, 3);
  (void) wait3(NULL, WNOHANG, NULL);

  printf("%d of %d target%s%scompleted, %lu valid password%s found\n", hydra_brains.targets - j - k - error, hydra_brains.targets, hydra_brains.targets == 1 ? " " : "s ",
         hydra_brains.found > 0 ? "successfully " : "", hydra_brains.found, hydra_brains.found == 1 ? "" : "s");
  if (error == 0 && j == 0) {
    process_restore = 0;
    unlink(RESTOREFILE);
  } else {
    if (hydra_options.cidr == 0) {
      printf("[INFO] Writing restore file because %d server scan%s could not be completed\n", j + error, j + error == 1 ? "" : "s");
      hydra_restore_write(1);
    }
  }
  if (error) {
    fprintf(stderr, "[ERROR] %d target%s disabled because of too many errors\n", error, error == 1 ? " was" : "s were");
    error = 1;
  }
  if (k) {
    fprintf(stderr, "[ERROR] %d target%s did not resolve or could not be connected\n", k, k == 1 ? "" : "s");
    error = 1;
  }
  if (j) {
    fprintf(stderr, "[ERROR] %d target%s did not complete\n", j, j == 1 ? "" : "s");
    error = 1;
  }
  // yeah we did it 
  printf("%s (%s) finished at %s\n", PROGRAM, RESOURCE, hydra_build_time());
  if (hydra_brains.ofp != NULL && hydra_brains.ofp != stdout)
    fclose(hydra_brains.ofp);

  fflush(NULL);
  if (error || j || exit_condition < 0)
    return -1;
  else
    return 0;
}
