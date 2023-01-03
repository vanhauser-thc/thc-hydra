/*
 * hydra (c) 2001-2023 by van Hauser / THC <vh@thc.org>
 * https://github.com/vanhauser-thc/thc-hydra
 *
 * Parallized network login hacker.
 * Please don't use in military or secret service organizations, or for illegal
 * purposes. This is a wish and is non-binding.
 * If you ignore this be sure you are not a good person though.
 *
 * License: GNU AFFERO GENERAL PUBLIC LICENSE v3.0, see LICENSE file
 */
#include "hydra.h"
#include "bfg.h"
#include <strings.h>

#ifdef LIBNCURSES
#include <curses.h>
#include <term.h>
#endif

void usage_oracle(const char *service);
void usage_oracle_listener(const char *service);
void usage_cvs(const char *service);
void usage_xmpp(const char *service);
void usage_pop3(const char *service);
void usage_rdp(const char *service);
void usage_s7_300(const char *service);
void usage_nntp(const char *service);
void usage_imap(const char *service);
void usage_smtp_enum(const char *service);
void usage_smtp(const char *service);
void usage_svn(const char *service);
void usage_ncp(const char *service);
void usage_firebird(const char *service);
void usage_mysql(const char *service);
void usage_mongodb(const char *service);
void usage_irc(const char *service);
void usage_postgres(const char *service);
void usage_telnet(const char *service);
void usage_sapr3(const char *service);
void usage_sshkey(const char *service);
void usage_cisco_enable(const char *service);
void usage_cisco(const char *service);
void usage_ldap(const char *service);
void usage_smb(const char *service);
void usage_http_form(const char *service);
void usage_http_proxy(const char *service);
void usage_http_proxy_urlenum(const char *service);
void usage_snmp(const char *service);
void usage_http(const char *service);
void usage_smb2(const char *service);

extern void service_asterisk(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_telnet(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_ftp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_ftps(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_pop3(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_vmauthd(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_imap(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_ldap2(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_ldap3(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_ldap3_cram_md5(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_ldap3_digest_md5(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_adam6500(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_cisco(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_cisco_enable(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_vnc(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_socks5(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_rexec(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_rlogin(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_rsh(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_nntp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_head(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_get(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_post(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_get_form(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_post_form(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_icq(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_pcnfs(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_mssql(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_cobaltstrike(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_cvs(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_snmp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_smtp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_smtp_enum(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_teamspeak(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_pcanywhere(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_proxy(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_xmpp(char *target, char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_irc(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_redis(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_http_proxy_urlenum(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_s7_300(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_rtsp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_rpcap(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);

// ADD NEW SERVICES HERE

#if defined(LIBSMBCLIENT)
extern int32_t service_smb2_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_smb2(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif

#ifdef HAVE_MATH_H
extern void service_mysql(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_mysql_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBPOSTGRES
extern void service_postgres(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_postgres_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBOPENSSL
extern void service_smb(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_smb_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_oracle_listener(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_oracle_listener_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_oracle_sid(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_oracle_sid_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_sip(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_sip_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBFREERDP
extern void service_rdp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_rdp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBSAPR3
extern void service_sapr3(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_sapr3_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBFIREBIRD
extern void service_firebird(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_firebird_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBAFP
extern void service_afp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_afp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBNCP
extern void service_ncp(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_ncp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBSSH
extern void service_ssh(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_ssh_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern void service_sshkey(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_sshkey_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBSVN
extern void service_svn(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_svn_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBORACLE
extern void service_oracle(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_oracle_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef HAVE_GCRYPT
extern void service_radmin2(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_radmin2_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBMCACHED
extern void service_mcached(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_mcached_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif
#ifdef LIBMONGODB
extern void service_mongodb(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_mongodb_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
#endif

extern int32_t service_adam6500_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_cisco_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_cisco_enable_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_cvs_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_smtp_enum_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_http_form_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_ftp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_http_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_icq_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_imap_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_irc_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_ldap_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_mssql_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_cobaltstrike_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_nntp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_pcanywhere_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_pcnfs_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_pop3_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_http_proxy_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_asterisk_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_redis_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_rexec_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_rlogin_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_rsh_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_smtp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_snmp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_socks5_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_teamspeak_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_telnet_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_http_proxy_urlenum_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_vmauthd_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_vnc_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_xmpp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_s7_300_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_rtsp_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
extern int32_t service_rpcap_init(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);

// ADD NEW SERVICES HERE
char *SERVICES = "adam6500 asterisk afp cisco cisco-enable cobaltstrike cvs firebird ftp[s] "
                 "http[s]-{head|get|post} http[s]-{get|post}-form http-proxy "
                 "http-proxy-urlenum icq imap[s] irc ldap2[s] ldap3[-{cram|digest}md5][s] "
                 "memcached mongodb mssql mysql ncp nntp oracle oracle-listener oracle-sid "
                 "pcanywhere pcnfs pop3[s] postgres radmin2 rdp redis rexec rlogin rpcap "
                 "rsh rtsp s7-300 sapr3 sip smb smb2 smtp[s] smtp-enum snmp socks5 ssh "
                 "sshkey svn teamspeak telnet[s] vmauthd vnc xmpp";

#define MAXBUF 520
#define MAXLINESIZE ((MAXBUF / 2) - 4)
#define MAXTASKS 64
#define MAXSERVERS 16
#define MAXFAIL 3
#define MAXENDWAIT 20
#define WAITTIME 32
#define TASKS 16
#define SKIPLOGIN 256
#define USLEEP_LOOP 10
#define MAX_LINES 50000000  // 50 millions, do not put more than 65millions
#define MAX_BYTES 500000000 // 500 millions, do not put more than 650millions

#define RESTOREFILE "./hydra.restore"

#define PROGRAM "Hydra"
#define VERSION "v9.5-dev"
#define AUTHOR "van Hauser/THC"
#define EMAIL "<vh@thc.org>"
#define AUTHOR2 "David Maciejak"
#define EMAIL2 "<david.maciejak@gmail.com>"
#define RESOURCE "https://github.com/vanhauser-thc/thc-hydra"

extern char *hydra_strcasestr(const char *haystack, const char *needle);
extern void hydra_tobase64(unsigned char *buf, int32_t buflen, int32_t bufsize);
extern char *hydra_string_replace(const char *string, const char *substr, const char *replacement);
extern char *hydra_address2string(char *address);
extern char *hydra_address2string_beautiful(char *address);
extern uint32_t colored_output;
extern char quiet;
extern int32_t do_retry;
extern int32_t old_ssl;

void hydra_kill_head(int32_t head_no, int32_t killit, int32_t fail);

// some enum definitions
typedef enum { HEAD_DISABLED = -1, HEAD_UNUSED = 0, HEAD_ACTIVE = 1 } head_state_t;

typedef enum { TARGET_ACTIVE = 0, TARGET_FINISHED = 1, TARGET_ERROR = 2, TARGET_UNRESOLVED = 3 } target_state_t;

// some structure definitions
typedef struct {
  pid_t pid;
  int32_t sp[2];
  int32_t target_no;
  char *current_login_ptr;
  char *current_pass_ptr;
  char reverse[256];
  head_state_t active;
  int32_t redo;
  time_t last_seen;
} hydra_head;

typedef struct {
  char *target;
  char ip[36];
  char *login_ptr;
  char *pass_ptr;
  uint64_t login_no;
  uint64_t pass_no;
  uint64_t sent;
  int32_t pass_state;
  int32_t use_count;
  target_state_t done;
  int32_t fail_count;
  int32_t redo_state;
  int32_t redo;
  int32_t ok;
  int32_t failed;
  int32_t skipcnt;
  int32_t port;
  char *redo_login[MAXTASKS * 2 + 2];
  char *redo_pass[MAXTASKS * 2 + 2];
  char *skiplogin[SKIPLOGIN];
  //  char *bfg_ptr[MAXTASKS];
} hydra_target;

typedef struct {
  int32_t active; // active tasks of hydra_options.max_use
  int32_t targets;
  int32_t finished;
  int32_t exit;
  uint64_t todo_all;
  uint64_t todo;
  uint64_t sent;
  uint64_t found;
  uint64_t countlogin;
  uint64_t countpass;
  size_t sizelogin;
  size_t sizepass;
  FILE *ofp;
} hydra_brain;

typedef struct {
  char *name;
  int32_t port;
  int32_t port_ssl;
} hydra_portlist;

// external vars
extern char *HYDRA_EXIT;
#if !defined(ANDROID) && !defined(__BIONIC__)
extern int32_t errno;
#endif
extern int32_t debug;
extern int32_t verbose;
extern int32_t waittime;
extern int32_t port;
extern int32_t found;
extern int32_t use_proxy;
extern int32_t proxy_count;
extern int32_t selected_proxy;
extern int32_t proxy_string_port[MAX_PROXY_COUNT];
extern char proxy_string_ip[MAX_PROXY_COUNT][36];
extern char proxy_string_type[MAX_PROXY_COUNT][10];
extern char *proxy_authentication[MAX_PROXY_COUNT];
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
int32_t prefer_ipv6 = 0, conwait = 0, loop_cnt = 0, fck = 0, options = 0, killed = 0;
int32_t child_head_no = -1, child_socket;
int32_t total_redo_count = 0;

// moved for restore feature
int32_t process_restore = 0, dont_unlink;
char *login_ptr = NULL, *pass_ptr = "", *csv_ptr = NULL, *servers_ptr = NULL;
size_t countservers = 1, sizeservers = 0;
char empty_login[2] = "", unsupported[500] = "";

// required to save stack memory
char snpbuf[MAXBUF];
int32_t snpdone, snp_is_redo, snpbuflen, snpi, snpj, snpdont;

#include "performance.h"

typedef void (*service_t)(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
typedef int32_t (*service_init_t)(char *ip, int32_t sp, unsigned char options, char *miscptr, FILE *fp, int32_t port, char *hostname);
typedef void (*service_usage_t)(const char *service);

#define SERVICE2(name, func)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   \
  { name, service_##func##_init, service_##func, NULL }
#define SERVICE(name)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          \
  { #name, service_##name##_init, service_##name, NULL }
#define SERVICE3(name, func)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   \
  { name, service_##func##_init, service_##func, usage_##func }

static const struct {
  const char *name;
  service_init_t init;
  service_t exec;
  service_usage_t usage;
} services[] = {SERVICE(adam6500),
#ifdef LIBAFP
                SERVICE(afp),
#endif
                SERVICE(asterisk),
                SERVICE3("cisco", cisco),
                SERVICE3("cisco-enable", cisco_enable),
                SERVICE3("cvs", cvs),
#ifdef LIBFIREBIRD
                SERVICE3("firebird", firebird),
#endif
                SERVICE(ftp),
                {"ftps", service_ftp_init, service_ftps, NULL},
                {"http-get", service_http_init, service_http_get, usage_http},
                {"http-get-form", service_http_form_init, service_http_get_form, usage_http_form},
                {"http-head", service_http_init, service_http_head, NULL},
                {"http-form", service_http_form_init, NULL, usage_http_form},
                {"http-post", NULL, service_http_post, usage_http},
                {"http-post-form", service_http_form_init, service_http_post_form, usage_http_form},
                SERVICE3("http-proxy", http_proxy),
                SERVICE3("http-proxy-urlenum", http_proxy_urlenum),
                SERVICE(icq),
                SERVICE3("imap", imap),
                SERVICE3("irc", irc),
                {"ldap", service_ldap_init, service_ldap2, usage_ldap},
                {"ldap2", service_ldap_init, service_ldap2, usage_ldap},
                {"ldap3", service_ldap_init, service_ldap3, usage_ldap},
                {"ldap3-crammd5", service_ldap_init, service_ldap3_cram_md5, usage_ldap},
                {"ldap3-digestmd5", service_ldap_init, service_ldap3_digest_md5, usage_ldap},
#ifdef LIBMCACHED
                {"memcached", service_mcached_init, service_mcached, NULL},
#endif
                SERVICE(mssql),
                SERVICE(cobaltstrike),
#ifdef LIBMONGODB
                SERVICE3("mongodb", mongodb),
#endif
#ifdef HAVE_MATH_H
                SERVICE3("mysql", mysql),
#endif
#ifdef LIBNCP
                SERVICE3("ncp", ncp),
#endif
                SERVICE3("nntp", nntp),
#ifdef LIBORACLE
                SERVICE3("oracle", oracle),
#endif
#ifdef LIBOPENSSL
                SERVICE3("oracle-listener", oracle_listener),
                SERVICE2("oracle-sid", oracle_sid),
#endif
                SERVICE(pcanywhere),
                SERVICE(pcnfs),
                SERVICE3("pop3", pop3),
#ifdef LIBPOSTGRES
                SERVICE3("postgres", postgres),
#endif
                SERVICE(redis),
                SERVICE(rexec),
#ifdef LIBFREERDP
                SERVICE3("rdp", rdp),
#endif
                SERVICE(rlogin),
                SERVICE(rsh),
                SERVICE(rtsp),
                SERVICE(rpcap),
                SERVICE3("s7-300", s7_300),
#ifdef LIBSAPR3
                SERVICE3("sarp3", sapr3),
#endif
#ifdef LIBOPENSSL
                SERVICE(sip),
                SERVICE3("smbnt", smb),
                SERVICE3("smb", smb),
#endif
#if defined(LIBSMBCLIENT)
                SERVICE3("smb2", smb2),
#endif
                SERVICE3("smtp", smtp),
                SERVICE3("smtp-enum", smtp_enum),
                SERVICE3("snmp", snmp),
                SERVICE(socks5),
#ifdef LIBSSH
                {"ssh", NULL, service_ssh, NULL},
                SERVICE3("sshkey", sshkey),
#endif
#ifdef LIBSVN
                SERVICE3("svn", svn),
#endif
                SERVICE(teamspeak),
                SERVICE3("telnet", telnet),
                SERVICE(vmauthd),
                SERVICE(vnc),
#ifdef HAVE_GCRYPT
                SERVICE(radmin2),
#endif
                {"xmpp", service_xmpp_init, NULL, usage_xmpp}};

#define PRINT_NORMAL(ext, text, ...) printf(text, ##__VA_ARGS__)
#define PRINT_EXTEND(ext, text, ...)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           \
  do {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         \
    if (ext)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   \
      printf(text, ##__VA_ARGS__);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             \
  } while (0)

int32_t                                   /*inline*/
check_flag(int32_t value, int32_t flag) { // inline does not compile with debug
  return (value & flag) == flag;
}

void help(int32_t ext) {
  PRINT_NORMAL(ext, "Syntax: hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | "
                    "[-C FILE]] [-e nsr]"
                    " [-o FILE] [-t TASKS] [-M FILE [-T TASKS]] [-w TIME] [-W "
                    "TIME] [-f] [-s PORT]"
#ifdef HAVE_MATH_H
                    " [-x MIN:MAX:CHARSET]"
#endif
                    " [-c TIME] [-ISOuvVd46] [-m MODULE_OPT] "
                    //"[server service [OPT]]|"
                    "[service://server[:PORT][/OPT]]\n");
  PRINT_NORMAL(ext, "\nOptions:\n");
  PRINT_EXTEND(ext, "  -R        restore a previous aborted/crashed session\n"
                    "  -I        ignore an existing restore file (don't wait 10 seconds)\n"
#ifdef LIBOPENSSL
                    "  -S        perform an SSL connect\n"
#endif
                    "  -s PORT   if the service is on a different default port, define it "
                    "here\n");
  PRINT_NORMAL(ext, "  -l LOGIN or -L FILE  login with LOGIN name, or load "
                    "several logins from FILE\n"
                    "  -p PASS  or -P FILE  try password PASS, or load several "
                    "passwords from FILE\n");
  PRINT_EXTEND(ext,
#ifdef HAVE_MATH_H
               "  -x MIN:MAX:CHARSET  password bruteforce generation, type "
               "\"-x -h\" to get help\n"
               "  -y        disable use of symbols in bruteforce, see above\n"
               "  -r        use a non-random shuffling method for option -x\n"
#endif
               "  -e nsr    try \"n\" null password, \"s\" login as pass "
               "and/or \"r\" reversed login\n"
               "  -u        loop around users, not passwords (effective! "
               "implied with -x)\n");
  PRINT_NORMAL(ext, "  -C FILE   colon separated \"login:pass\" format, "
                    "instead of -L/-P options\n"
                    "  -M FILE   list of servers to attack, one entry per "
                    "line, ':' to specify port\n");
  PRINT_EXTEND(ext, "  -o FILE   write found login/password pairs to FILE instead of stdout\n"
                    "  -b FORMAT specify the format for the -o FILE: text(default), json, "
                    "jsonv1\n"
                    "  -f / -F   exit when a login/pass pair is found (-M: -f per host, -F "
                    "global)\n");
  PRINT_NORMAL(ext,
               "  -t TASKS  run TASKS number of connects in parallel per "
               "target (default: %d)\n",
               TASKS);
  PRINT_EXTEND(ext,
               "  -T TASKS  run TASKS connects in parallel overall (for -M, default: "
               "%d)\n"
               "  -w / -W TIME  wait time for a response (%d) / between connects per "
               "thread (%d)\n"
#ifdef MSG_PEEK
               "  -c TIME   wait time per login attempt over all threads (enforces -t "
               "1)\n"
#endif
               "  -4 / -6   use IPv4 (default) / IPv6 addresses (put always in [] also "
               "in -M)\n"
               "  -v / -V / -d  verbose mode / show login+pass for each attempt / debug "
               "mode \n"
               "  -O        use old SSL v2 and v3\n"
               "  -K        do not redo failed attempts (good for -M mass scanning)\n"
               "  -q        do not print messages about connection errors\n",
               MAXTASKS, WAITTIME, conwait);
  PRINT_NORMAL(ext, "  -U        service module usage details\n"
                    "  -m OPT    options specific for a module, see -U output for "
                    "information\n"
                    "  -h        more command line options (COMPLETE HELP)\n"
                    "  server    the target: DNS, IP or 192.168.0.0/24 (this OR the -M "
                    "option)\n"
                    "  service   the service to crack (see below for supported protocols)\n"
                    "  OPT       some service modules support additional input (-U for "
                    "module help)\n");
  PRINT_NORMAL(ext,
               "\nSupported services: %s\n"
               "\n%s is a tool to guess/crack valid login/password pairs.\n"
               "Licensed under AGPL v3.0. The newest version is always available at;\n%s\n"
               "Please don't use in military or secret service organizations, or for illegal\n"
               "purposes. (This is a wish and non-binding - most such people do not care about\n"
               "laws and ethics anyway - and tell themselves they are one of the good ones.)\n",
               SERVICES, PROGRAM, RESOURCE);

  if (ext && strlen(unsupported) > 0) {
    if (unsupported[strlen(unsupported) - 1] == ' ')
      unsupported[strlen(unsupported) - 1] = 0;
    printf("These services were not compiled in: %s.\n", unsupported);
  }
  PRINT_EXTEND(ext, "\nUse HYDRA_PROXY_HTTP or HYDRA_PROXY environment variables for a proxy "
                    "setup.\n"
                    "E.g. %% export HYDRA_PROXY=socks5://l:p@127.0.0.1:9150 (or: socks4:// "
                    "connect://)\n"
                    "     %% export HYDRA_PROXY=connect_and_socks_proxylist.txt  (up to 64 "
                    "entries)\n"
                    "     %% export HYDRA_PROXY_HTTP=http://login:pass@proxy:8080\n"
                    "     %% export HYDRA_PROXY_HTTP=proxylist.txt  (up to 64 entries)\n");
  PRINT_NORMAL(ext, "\nExample%s:%s  hydra -l user -P passlist.txt ftp://192.168.0.1\n", ext == 0 ? "" : "s", ext == 0 ? "" : "\n");
  PRINT_EXTEND(ext, "  hydra -L userlist.txt -p defaultpw imap://192.168.0.1/PLAIN\n"
                    "  hydra -C defaults.txt -6 pop3s://[2001:db8::1]:143/TLS:DIGEST-MD5\n"
                    "  hydra -l admin -p password ftp://[192.168.0.0/24]/\n"
                    "  hydra -L logins.txt -P pws.txt -M targets.txt ssh\n");
  exit(-1);
}

void help_bfg() {
  printf("Hydra bruteforce password generation option usage:\n\n"
         "  -x MIN:MAX:CHARSET\n\n"
         "     MIN     is the minimum number of characters in the password\n"
         "     MAX     is the maximum number of characters in the password\n"
         "     CHARSET is a specification of the characters to use in the "
         "generation\n"
         "             valid CHARSET values are: 'a' for lowercase letters,\n"
         "             'A' for uppercase letters, '1' for numbers, and for all "
         "others,\n"
         "             just add their real representation.\n"
         "  -y         disable the use of the above letters as placeholders\n"
         "Examples:\n"
         "   -x 3:5:a  generate passwords from length 3 to 5 with all "
         "lowercase letters\n"
         "   -x 5:8:A1 generate passwords from length 5 to 8 with uppercase "
         "and numbers\n"
         "   -x 1:3:/  generate passwords from length 1 to 3 containing only "
         "slashes\n"
         "   -x 5:5:/%%,.-  generate passwords with length 5 which consists "
         "only of /%%,.-\n"
         "   -x 3:5:aA1 -y generate passwords from length 3 to 5 with a, A and "
         "1 only\n"
         "\nThe bruteforce mode was made by Jan Dlabal, "
         "http://houbysoft.com/bfg/\n");
  exit(-1);
}

void module_usage() {
  int32_t i;

  printf("\nHelp for module "
         "%s:\n================================================================"
         "============\n",
         hydra_options.service);
  if (strncmp(hydra_options.service, "https-", 6) == 0)
    memmove(hydra_options.service + 4, hydra_options.service + 5, strlen(hydra_options.service) - 4);
  for (i = 0; i < sizeof(services) / sizeof(services[0]); i++) {
    if (strcmp(hydra_options.service, services[i].name) == 0) {
      if (services[i].usage) {
        services[i].usage(hydra_options.service);
        exit(0);
      }
    }
  }

  printf("The Module %s does not need or support optional parameters\n", hydra_options.service);
  exit(0);
}

#define STR_NULL(s) ((s) == NULL ? "(null)" : (s))

void hydra_debug(int32_t force, char *string) {
  int32_t active = 0, inactive = 0, i;

  if (!debug && !force)
    return;

  printf("[DEBUG] Code: %s   Time: %" hPRIu64 "\n", string, (uint64_t)time(NULL));
  printf("[DEBUG] Options: mode %d  ssl %d  restore %d  showAttempt %d  tasks "
         "%d  max_use %d tnp %d  tpsal %d  tprl %d  exit_found %d  miscptr %s  "
         "service %s\n",
         hydra_options.mode, hydra_options.ssl, hydra_options.restore, hydra_options.showAttempt, hydra_options.tasks, hydra_options.max_use, hydra_options.try_null_password, hydra_options.try_password_same_as_login, hydra_options.try_password_reverse_login, hydra_options.exit_found, STR_NULL(hydra_options.miscptr), hydra_options.service);

  printf("[DEBUG] Brains: active %d  targets %d  finished %d  todo_all %" hPRIu64 "  todo %" hPRIu64 "  sent %" hPRIu64 "  found %" hPRIu64 "  countlogin %" hPRIu64 "  sizelogin %" hPRIu64 "  countpass %" hPRIu64 "  sizepass %" hPRIu64 "\n", hydra_brains.active, hydra_brains.targets, hydra_brains.finished, hydra_brains.todo_all + total_redo_count, hydra_brains.todo, hydra_brains.sent, hydra_brains.found, (uint64_t)hydra_brains.countlogin, (uint64_t)hydra_brains.sizelogin, (uint64_t)hydra_brains.countpass,
         (uint64_t)hydra_brains.sizepass);

  for (i = 0; i < hydra_brains.targets; i++) {
    hydra_target *target = hydra_targets[i];
    printf("[DEBUG] Target %d - target %s  ip %s  login_no %" hPRIu64 "  pass_no %" hPRIu64 "  sent %" hPRIu64 "  pass_state %d  redo_state %d (%d redos)  use_count %d  failed %d "
           " done %d  fail_count %d  login_ptr %s  pass_ptr %s\n",
           i, STR_NULL(target->target), hydra_address2string_beautiful(target->ip), target->login_no, target->pass_no, target->sent, target->pass_state, target->redo_state, target->redo, target->use_count, target->failed, target->done, target->fail_count, STR_NULL(target->login_ptr), STR_NULL(target->pass_ptr));
  }

  if (hydra_heads == NULL)
    return;

  for (i = 0; i < hydra_options.max_use; i++) {
    if (hydra_heads[i]->active >= HEAD_UNUSED) {
      printf("[DEBUG] Task %d - pid %d  active %d  redo %d  current_login_ptr "
             "%s  current_pass_ptr %s\n",
             i, (int32_t)hydra_heads[i]->pid, hydra_heads[i]->active, hydra_heads[i]->redo, STR_NULL(hydra_heads[i]->current_login_ptr), STR_NULL(hydra_heads[i]->current_pass_ptr));
      if (hydra_heads[i]->active == HEAD_UNUSED)
        inactive++;
      else
        active++;
    }
  }
  printf("[DEBUG] Tasks %d inactive  %d active\n", inactive, active);
}

void bail(char *text) {
  fprintf(stderr, "[ERROR] %s\n", text);
  exit(-1);
}

void hydra_restore_write(int32_t print_msg) {
  FILE *f;
  hydra_brain brain;
  char mynull[4] = {0, 0, 0, 0}, buf[4];
  int32_t i = 0, j = 0;
  hydra_head hh;

  if (process_restore != 1)
    return;

  for (i = 0; i < hydra_brains.targets; i++)
    if (hydra_targets[j]->done != TARGET_FINISHED && hydra_targets[j]->done != TARGET_UNRESOLVED)
      j++;
  if (j == 0) {
    process_restore = 0;
    return;
  }

  if ((f = fopen(RESTOREFILE, "w")) == NULL) {
    fprintf(stderr, "[ERROR] Can not create restore file (%s) - ", RESTOREFILE);
    perror("");
    process_restore = 0;
    return;
  } else if (debug)
    printf("[DEBUG] Writing restore file... ");

  fprintf(f, "%s\n", PROGRAM);
  buf[0] = VERSION[1];
  buf[1] = VERSION[3];
  buf[2] = sizeof(int32_t) % 256;
  buf[3] = sizeof(hydra_target *) % 256;
  fwrite(buf, 1, 4, f);
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
  fck = fwrite(login_ptr, hydra_brains.sizelogin + hydra_brains.countlogin + 8, 1, f);
  if (hydra_options.colonfile == NULL || hydra_options.colonfile == empty_login)
    fck = fwrite(pass_ptr, hydra_brains.sizepass + hydra_brains.countpass + 8, 1, f);
  for (j = 0; j < hydra_brains.targets; j++)
    if (hydra_targets[j]->done != TARGET_FINISHED) {
      fck = fwrite(hydra_targets[j], sizeof(hydra_target), 1, f);
      fprintf(f, "%s\n%d\n%d\n", hydra_targets[j]->target == NULL ? "" : hydra_targets[j]->target, (int32_t)(hydra_targets[j]->login_ptr - login_ptr), (int32_t)(hydra_targets[j]->pass_ptr - pass_ptr));
      fprintf(f, "%s\n%s\n", hydra_targets[j]->login_ptr, hydra_targets[j]->pass_ptr);
      if (hydra_targets[j]->redo)
        for (i = 0; i < hydra_targets[j]->redo; i++)
          fprintf(f, "%s\n%s\n", hydra_targets[j]->redo_login[i], hydra_targets[j]->redo_pass[i]);
      if (hydra_targets[j]->skipcnt)
        for (i = 0; i < hydra_targets[j]->skipcnt; i++)
          fprintf(f, "%s\n", hydra_targets[j]->skiplogin[i]);
    }
  for (j = 0; j < hydra_options.max_use; j++) {
    memcpy((char *)&hh, hydra_heads[j], sizeof(hydra_head));
    if (j == 0 && debug) {
      printf("[DEBUG] sizeof hydra_head: %lu\n", sizeof(hydra_head));
      printf("[DEBUG] memcmp: %d\n", memcmp(hydra_heads[j], &hh, sizeof(hydra_head)));
    }
    hh.active = 0; // re-enable disabled heads
    if ((hh.current_login_ptr != NULL && hh.current_login_ptr != empty_login) || (hh.current_pass_ptr != NULL && hh.current_pass_ptr != empty_login)) {
      hh.redo = 1;
      if (print_msg && debug)
        printf("[DEBUG] we will redo the following combination: target %s  "
               "child %d  login \"%s\"  pass \"%s\"\n",
               hydra_targets[hh.target_no]->target, j, hh.current_login_ptr, hh.current_pass_ptr);
    }
    fck = fwrite((char *)&hh, sizeof(hydra_head), 1, f);
    if (hh.redo /* && (hydra_options.bfg == 0 || (hh.current_pass_ptr == hydra_targets[hh.target_no]->bfg_ptr[j] && isprint((char) hh.current_pass_ptr[0]))) */)
      fprintf(f, "%s\n%s\n", hh.current_login_ptr == NULL ? "" : hh.current_login_ptr, hh.current_pass_ptr == NULL ? "" : hh.current_pass_ptr);
    else
      fprintf(f, "\n\n");
  }

  fprintf(f, "%s\n", PROGRAM);
  fclose(f);
  if (debug)
    printf("[DEBUG] done writing session file\n");
  if (print_msg)
    printf("The session file ./hydra.restore was written. Type \"hydra -R\" to "
           "resume session.\n");
  hydra_debug(0, "hydra_restore_write()");
}

void hydra_restore_read() {
  FILE *f;
  char mynull[4], buf[4];
  int32_t i, j, orig_debug = debug;
  char out[1024];

  printf("[INFORMATION] reading restore file %s\n", RESTOREFILE);
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

  if ((fck = (int32_t)fread(buf, 1, 4, f)) != 4) {
    fprintf(stderr, "[ERROR] invalid restore file (platform)\n");
    exit(-1);
  }
  if (buf[0] == 0 || buf[1] == 0) {
    fprintf(stderr, "[ERROR] restore file is prior hydra version v8.5!\n");
    exit(-1);
  }
  if (buf[0] != VERSION[1] || buf[1] != VERSION[3])
    fprintf(stderr,
            "[WARNING] restore file was created by version %c.%c, this is "
            "version %s\n",
            buf[0], buf[1], VERSION);
  if (buf[2] != sizeof(int32_t) % 256 || buf[3] != sizeof(hydra_head *) % 256) {
    fprintf(stderr, "[ERROR] restore file was created on a different, "
                    "incompatible processor platform!\n");
    exit(-1);
  }

  fck = (int32_t)fread(&bf_options, sizeof(bf_options), 1, f);
  fck = (int32_t)fread(mynull, sizeof(mynull), 1, f);
  if (debug)
    printf("[DEBUG] reading restore file: Step 1 complete\n");
  if (mynull[0] + mynull[1] + mynull[2] + mynull[3] == 0) {
    bf_options.crs = NULL;
  } else {
    bf_options.crs = malloc(BF_CHARSMAX);
    memcpy(bf_options.crs, mynull, sizeof(mynull));
    fck = fread(bf_options.crs + sizeof(mynull), BF_CHARSMAX - sizeof(mynull), 1, f);
  }
  if (debug)
    printf("[DEBUG] reading restore file: Step 2 complete\n");

  fck = (int32_t)fread(&hydra_brains, sizeof(hydra_brain), 1, f);
  hydra_brains.ofp = stdout;
  fck = (int32_t)fread(&hydra_options, sizeof(hydra_option), 1, f);
  hydra_options.restore = 1;
  verbose = hydra_options.verbose;
  debug = hydra_options.debug;
  if (debug || orig_debug)
    printf("[DEBUG] run_debug %d, orig_debug %d\n", debug, orig_debug);
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
  if (debug)
    printf("[DEBUG] reading restore file: Step 3 complete\n");
  if (strlen(out) > 0) {
    hydra_options.outfile_ptr = malloc(strlen(out) + 1);
    strcpy(hydra_options.outfile_ptr, out);
  } else
    hydra_options.outfile_ptr = NULL;
  if (debug)
    printf("[DEBUG] reading restore file: Step 4 complete\n");
  sck = fgets(out, sizeof(out), f);
  if (out[0] != 0 && out[strlen(out) - 1] == '\n')
    out[strlen(out) - 1] = 0;
  if (debug)
    printf("[DEBUG] reading restore file: Step 5 complete\n");
  if (strlen(out) == 0)
    hydra_options.miscptr = NULL;
  else {
    hydra_options.miscptr = malloc(strlen(out) + 1);
    strcpy(hydra_options.miscptr, out);
  }
  if (debug)
    printf("[DEBUG] reading restore file: Step 6 complete\n");
  sck = fgets(out, sizeof(out), f);
  if (out[0] != 0 && out[strlen(out) - 1] == '\n')
    out[strlen(out) - 1] = 0;
  if (debug)
    printf("[DEBUG] reading restore file: Step 7 complete\n");
  hydra_options.service = malloc(strlen(out) + 1);
  strcpy(hydra_options.service, out);
  if (debug)
    printf("[DEBUG] reading restore file: Step 8 complete\n");

  login_ptr = malloc(hydra_brains.sizelogin + hydra_brains.countlogin + 8);
  if (!login_ptr) {
    fprintf(stderr, "Error: malloc(%lu) failed\n", hydra_brains.sizelogin + hydra_brains.countlogin + 8);
    exit(-1);
  }
  fck = (int32_t)fread(login_ptr, hydra_brains.sizelogin + hydra_brains.countlogin + 8, 1, f);
  if (debug)
    printf("[DEBUG] reading restore file: Step 9 complete\n");
  if (!check_flag(hydra_options.mode, MODE_COLON_FILE)) { // NOT colonfile mode
    pass_ptr = malloc(hydra_brains.sizepass + hydra_brains.countpass + 8);
    if (!pass_ptr) {
      fprintf(stderr, "Error: malloc(%lu) failed\n", hydra_brains.sizepass + hydra_brains.countpass + 8);
      exit(-1);
    }
    fck = (int32_t)fread(pass_ptr, hydra_brains.sizepass + hydra_brains.countpass + 8, 1, f);
  } else {                                 // colonfile mode
    hydra_options.colonfile = empty_login; // dummy
    pass_ptr = csv_ptr = login_ptr;
  }
  if (debug)
    printf("[DEBUG] reading restore file: Step 10 complete\n");

  hydra_targets = (hydra_target **)malloc((hydra_brains.targets + 3) * sizeof(hydra_target *));
  if (!hydra_targets) {
    fprintf(stderr, "Error: malloc(%lu) failed\n", (hydra_brains.targets + 3) * sizeof(hydra_target *));
    exit(-1);
  }
  for (j = 0; j < hydra_brains.targets; j++) {
    hydra_targets[j] = malloc(sizeof(hydra_target));
    if (!hydra_targets[j]) {
      fprintf(stderr, "Error: malloc(%lu) failed\n", sizeof(hydra_target));
      exit(-1);
    }
    fck = (int32_t)fread(hydra_targets[j], sizeof(hydra_target), 1, f);
    sck = fgets(out, sizeof(out), f);
    if (out[0] != 0 && out[strlen(out) - 1] == '\n')
      out[strlen(out) - 1] = 0;
    hydra_targets[j]->target = malloc(strlen(out) + 1);
    strcpy(hydra_targets[j]->target, out);
    sck = fgets(out, sizeof(out), f);
    hydra_targets[j]->login_ptr = login_ptr + atoi(out);
    sck = fgets(out, sizeof(out), f);
    hydra_targets[j]->pass_ptr = pass_ptr + atoi(out);
    sck = fgets(out, sizeof(out), f); // target login_ptr, ignord
    sck = fgets(out, sizeof(out), f);
    if (hydra_options.bfg) {
      if (out[0] != 0 && out[strlen(out) - 1] == '\n')
        out[strlen(out) - 1] = 0;
      hydra_targets[j]->pass_ptr = malloc(strlen(out) + 1);
      strcpy(hydra_targets[j]->pass_ptr, out);
    }
    if (hydra_targets[j]->redo > 0) {
      if (debug)
        printf("[DEBUG] target %d redo %d\n", j, hydra_targets[j]->redo);
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
  if (debug)
    printf("[DEBUG] reading restore file: Step 11 complete\n");
  hydra_heads = malloc(sizeof(hydra_head *) * hydra_options.max_use);
  if (!hydra_heads) {
    fprintf(stderr, "Error: malloc(%lu) failed\n", sizeof(hydra_head *) * hydra_options.max_use);
    exit(-1);
  }
  for (j = 0; j < hydra_options.max_use; j++) {
    hydra_heads[j] = malloc(sizeof(hydra_head));
    if (!hydra_heads[j]) {
      fprintf(stderr, "Error: malloc(%lu) failed\n", sizeof(hydra_head));
      exit(-1);
    }
    fck = (int32_t)fread(hydra_heads[j], sizeof(hydra_head), 1, f);
    hydra_heads[j]->sp[0] = -1;
    hydra_heads[j]->sp[1] = -1;
    sck = fgets(out, sizeof(out), f);
    if (hydra_heads[j]->redo) {
      if (debug)
        printf("[DEBUG] head %d redo\n", j);
      if (out[0] != 0 && out[strlen(out) - 1] == '\n')
        out[strlen(out) - 1] = 0;
      hydra_heads[j]->current_login_ptr = malloc(strlen(out) + 1);
      strcpy(hydra_heads[j]->current_login_ptr, out);
    }
    sck = fgets(out, sizeof(out), f);
    if (hydra_heads[j]->redo) {
      if (out[0] != 0 && out[strlen(out) - 1] == '\n')
        out[strlen(out) - 1] = 0;
      if (debug)
        printf("[DEBUG] TEMP head %d: pass == %s, login == %s\n", j, out, hydra_heads[j]->current_login_ptr);
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
  if (debug)
    printf("[DEBUG] reading restore file: Step 12 complete\n");
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

void killed_childs(int32_t signo) {
  int32_t pid, i;

  killed++;
  pid = waitpid(-1, NULL, WNOHANG);
  for (i = 0; i < hydra_options.max_use; i++) {
    if (pid == hydra_heads[i]->pid) {
      hydra_heads[i]->pid = -1;
      hydra_kill_head(i, 1, 0);
      return;
    }
  }
}

void killed_childs_report(int32_t signo) {
  // if (debug)
  printf("[ERROR] children crashed! (%d)\n", child_head_no);
  fck = write(child_socket, "E", 1);
  _exit(-1);
}

void kill_children(int32_t signo) {
  int32_t i;

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

uint64_t countlines(FILE *fd, int32_t colonmode) {
  size_t clines = 0;
  char *buf = malloc(MAXLINESIZE);
  int32_t only_one_empty_line = 0;

#ifdef HAVE_ZLIB
  gzFile fp = gzdopen(fileno(fd), "r");
#else
  FILE *fp = fd;
#endif

  size_of_data = 0;

#ifdef HAVE_ZLIB
  while (!gzeof(fp)) {
    if (gzgets(fp, buf, MAXLINESIZE) != NULL) {
#else
  while (!feof(fp)) {
    if (fgets(buf, MAXLINESIZE, fp) != NULL) {
#endif
      size_of_data += strlen(buf);
      if (buf[0] != 0) {
        if (buf[0] == '\r' || buf[0] == '\n') {
          if (only_one_empty_line == 0) {
            only_one_empty_line = 1;
            clines++;
          }
        } else {
          clines++;
        }
      }
    }
  }
#ifdef HAVE_ZLIB
  gzrewind(fp);
#else
  rewind(fp);
#endif
  free(buf);
  return clines;
}

void fill_mem(char *ptr, FILE *fd, int32_t colonmode) {
  char tmp[MAXBUF + 4] = "", *ptr2;
  uint32_t len;
  int32_t only_one_empty_line = 0;

  int read_flag = 0;
#ifdef HAVE_ZLIB
  gzFile fp = gzdopen(fileno(fd), "r");

  while (!gzeof(fp) && !read_flag) {
    if (gzgets(fp, tmp, MAXLINESIZE) != NULL) {
#else
  FILE *fp = fd;

  while (!feof(fp) && !read_flag) {
    if (fgets(tmp, MAXLINESIZE, fp) != NULL) {
#endif
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
            if ((ptr2 = strchr(tmp, ':')) == NULL) {
              fprintf(stderr,
                      "[ERROR] invalid line in colon file (-C), missing colon "
                      "in line: %s\n",
                      tmp);
              exit(-1);
            } else {
              *ptr2 = 0;
            }
          }
          memcpy(ptr, tmp, len);
          ptr += len;
          *ptr = '\0';
          ptr++;
        }
      }
    } else {
      read_flag = 1;
    }
  }
#ifdef HAVE_ZLIB
  gzclose(fp);
#else
  fclose(fp);
#endif
}

char *hydra_build_time() {
  static char datetime[24];
  struct tm *the_time;
  time_t epoch;

  time(&epoch);
  the_time = localtime(&epoch);
  strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", the_time);
  return (char *)&datetime;
}

void hydra_service_init(int32_t target_no) {
  int32_t x = 99;
  int32_t i;
  hydra_target *t = hydra_targets[target_no];
  char *miscptr = hydra_options.miscptr;
  FILE *ofp = hydra_brains.ofp;

  for (i = 0; x == 99 && i < sizeof(services) / sizeof(services[0]); i++) {
    if (strcmp(hydra_options.service, services[i].name) == 0) {
      if (services[i].init) {
        x = services[i].init(t->ip, -1, options, miscptr, ofp, t->port, t->target);
        break;
      }
    }
  }

  // dirty workaround here:
#ifdef LIBSSH
  if (strcmp(hydra_options.service, "ssh") == 0)
    x = service_ssh_init(t->ip, -1, options, login_ptr, ofp, t->port, t->target);
#endif

  if (x != 0 && x != 99) {
    if (x > 0 && x < 4)
      hydra_targets[target_no]->done = x;
    else
      hydra_targets[target_no]->done = TARGET_ERROR;
    hydra_brains.finished++;
    if (hydra_brains.targets == 1) {
      if (hydra_brains.ofp != NULL && hydra_brains.ofp != stdout) {
        if (hydra_options.outfile_format == FORMAT_JSONV1) {
          char json_error[120];
          snprintf(json_error, sizeof(json_error), "[ERROR] unexpected result connecting to target %s port %d", hydra_address2string_beautiful(t->ip), t->port);
          fprintf(hydra_brains.ofp,
                  "\n\t],\n\"success\": false,\n\"errormessages\": [ \"%s\" "
                  "],\n\"quantityfound\": %" hPRIu64 "   }\n",
                  json_error, hydra_brains.found);
        }
        fclose(hydra_brains.ofp);
      }
      exit(-1);
    }
  }
}

int32_t hydra_spawn_head(int32_t head_no, int32_t target_no) {
  int32_t i;

  if (head_no < 0 || head_no >= hydra_options.max_use || target_no < 0 || target_no >= hydra_brains.targets) {
    if (verbose > 1 || debug)
      printf("[DEBUG-ERROR] spawn_head: head_no %d, target_no %d\n", head_no, target_no);
    return -1;
  }

  if (hydra_heads[head_no]->active == HEAD_DISABLED) {
    printf("[DEBUG-ERROR] child %d should not be respawned!\n", head_no);
    return -1;
  }

  if (socketpair(PF_UNIX, SOCK_STREAM, 0, hydra_heads[head_no]->sp) == 0) {
    child_head_no = head_no;
    if ((hydra_heads[head_no]->pid = fork()) == 0) { // THIS IS THE CHILD
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

      hydra_target *t = hydra_targets[target_no];
      int32_t sp = hydra_heads[head_no]->sp[1];
      char *miscptr = hydra_options.miscptr;
      FILE *ofp = hydra_brains.ofp;
      hydra_target *head_target = hydra_targets[hydra_heads[head_no]->target_no];
      for (i = 0; i < sizeof(services) / sizeof(services[0]); i++) {
        if (strcmp(hydra_options.service, services[i].name) == 0) {
          if (services[i].exec) {
            services[i].exec(t->ip, sp, options, miscptr, ofp, t->port, head_target->target);
            // just in case a module returns (which it shouldnt) we let it exit
            // here
            exit(-1);
          }
        }
      }

      // FIXME: dirty workaround here
      if (strcmp(hydra_options.service, "xmpp") == 0) {
        service_xmpp(hydra_targets[target_no]->target, hydra_targets[target_no]->ip, hydra_heads[head_no]->sp[1], options, hydra_options.miscptr, hydra_brains.ofp, hydra_targets[target_no]->port, hydra_targets[hydra_heads[head_no]->target_no]->target);
      }

      // just in case a module returns (which it shouldnt) we let it exit here
      exit(-1);
    } else {
      child_head_no = -1;
      if (hydra_heads[head_no]->pid > 0) {
        fck = write(hydra_heads[head_no]->sp[1], "n",
                    1); // yes, a small "n" - this way we can distinguish later
                        // if the client successfully tested a pair and is
                        // requesting a new one or the mother did that
        (void)fcntl(hydra_heads[head_no]->sp[0], F_SETFL, O_NONBLOCK);
        if (hydra_heads[head_no]->redo != 1)
          hydra_heads[head_no]->target_no = target_no;
        hydra_heads[head_no]->active = HEAD_ACTIVE;
        hydra_targets[hydra_heads[head_no]->target_no]->use_count++;
        hydra_brains.active++;
        hydra_heads[head_no]->last_seen = time(NULL);
        if (debug)
          printf("[DEBUG] child %d spawned for target %d with pid %d\n", head_no, hydra_heads[head_no]->target_no, hydra_heads[head_no]->pid);
      } else {
        perror("[ERROR] Fork for children failed");
        hydra_heads[head_no]->sp[0] = -1;
        hydra_heads[head_no]->active = HEAD_UNUSED;
        return -1;
      }
    }
  } else {
    perror("[ERROR] socketpair creation failed");
    hydra_heads[head_no]->sp[0] = -1;
    hydra_heads[head_no]->active = HEAD_UNUSED;
    return -1;
  }
  return 0;
}

int32_t hydra_lookup_port(char *service) {
  int32_t i = 0, port = -2;

  hydra_portlist hydra_portlists[] = {{"ftp", PORT_FTP, PORT_FTP_SSL},
                                      {"ftps", PORT_FTP, PORT_FTP_SSL},
                                      {"http-head", PORT_HTTP, PORT_HTTP_SSL},
                                      {"http-post", PORT_HTTP, PORT_HTTP_SSL},
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
                                      {"memcached", PORT_MCACHED, PORT_MCACHED_SSL},
                                      {"mongodb", PORT_MONGODB, PORT_MONGODB},
                                      {"mssql", PORT_MSSQL, PORT_MSSQL_SSL},
                                      {"cobaltstrike", PORT_COBALTSTRIKE, PORT_COBALTSTRIKE_SSL},
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
                                      {"smb2", PORT_SMBNT, PORT_SMBNT_SSL},
                                      {"smbnt", PORT_SMBNT, PORT_SMBNT_SSL},
                                      {"socks5", PORT_SOCKS5, PORT_SOCKS5_SSL},
                                      {"ssh", PORT_SSH, PORT_SSH_SSL},
                                      {"sshkey", PORT_SSH, PORT_SSH_SSL},
                                      {"telnet", PORT_TELNET, PORT_TELNET_SSL},
                                      {"adam6500", PORT_ADAM6500, PORT_ADAM6500_SSL},
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
                                      {"rtsp", PORT_RTSP, PORT_RTSP_SSL},
                                      {"rpcap", PORT_RPCAP, PORT_RPCAP_SSL},
                                      {"radmin2", PORT_RADMIN2, PORT_RADMIN2},
                                      // ADD NEW SERVICES HERE - add new port numbers to hydra.h
                                      {"", PORT_NOPORT, PORT_NOPORT}};

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
void hydra_kill_head(int32_t head_no, int32_t killit, int32_t fail) {
  if (debug)
    printf("[DEBUG] head_no %d, kill %d, fail %d\n", head_no, killit, fail);
  if (head_no < 0)
    return;
  if (hydra_heads[head_no]->active == HEAD_ACTIVE || (hydra_heads[head_no]->sp[0] > 2 && hydra_heads[head_no]->sp[1] > 2)) {
    close(hydra_heads[head_no]->sp[0]);
    close(hydra_heads[head_no]->sp[1]);
  }
  if (killit) {
    if (hydra_heads[head_no]->pid > 0)
      kill(hydra_heads[head_no]->pid, SIGTERM);
    hydra_brains.active--;
  }
  if (hydra_heads[head_no]->active == HEAD_ACTIVE) {
    hydra_heads[head_no]->active = HEAD_UNUSED;
    hydra_targets[hydra_heads[head_no]->target_no]->use_count--;
  }
  if (fail == 1) {
    if (hydra_options.cidr != 1)
      hydra_heads[head_no]->redo = 1;
  } else if (fail == 2) {
    if (hydra_options.cidr != 1)
      hydra_heads[head_no]->active = HEAD_DISABLED;
    if (hydra_heads[head_no]->target_no >= 0)
      hydra_targets[hydra_heads[head_no]->target_no]->failed++;
  } else if (fail == 3) {
    hydra_heads[head_no]->active = HEAD_DISABLED;
    if (hydra_heads[head_no]->target_no >= 0)
      hydra_targets[hydra_heads[head_no]->target_no]->failed++;
  }
  if (hydra_heads[head_no]->pid > 0 && killit)
    kill(hydra_heads[head_no]->pid, SIGKILL);
  hydra_heads[head_no]->pid = -1;
  if (fail < 1 && hydra_heads[head_no]->target_no >= 0 && hydra_options.bfg && hydra_targets[hydra_heads[head_no]->target_no]->pass_state == 3 && strlen(hydra_heads[head_no]->current_pass_ptr) > 0 && hydra_heads[head_no]->current_pass_ptr != hydra_heads[head_no]->current_login_ptr) {
    free(hydra_heads[head_no]->current_pass_ptr);
    hydra_heads[head_no]->current_pass_ptr = empty_login;
    //    hydra_bfg_remove(head_no);
    //    hydra_targets[hydra_heads[head_no]->target_no]->bfg_ptr[head_no] =
    //    NULL;
  }
  (void)waitpid(-1, NULL, WNOHANG);
}

void hydra_increase_fail_count(int32_t target_no, int32_t head_no) {
  int32_t i, k, maxfail = 0;

  if (target_no < 0 || hydra_options.skip_redo)
    return;

  if (hydra_targets[target_no]->ok) {
    const int32_t tasks = hydra_options.tasks;
    const int32_t success = tasks - hydra_targets[target_no]->failed;
    const int32_t t = tasks < 5 ? 6 - tasks : 1;
    const int32_t s = success < 5 ? 6 - success : 1;
    maxfail = MAXFAIL + t + s + 2;
  }

  hydra_targets[target_no]->fail_count++;
  if (debug)
    printf("[DEBUG] hydra_increase_fail_count: %d >= %d => disable\n", hydra_targets[target_no]->fail_count, maxfail);
  if (hydra_targets[target_no]->fail_count >= maxfail) {
    k = 0;
    for (i = 0; i < hydra_options.max_use; i++)
      if (hydra_heads[i]->active >= HEAD_UNUSED && hydra_heads[i]->target_no == target_no)
        k++;
    if (k <= 1) {
      // we need to put this in a list, otherwise we fail one login+pw test
      if (hydra_targets[target_no]->done == TARGET_ACTIVE && hydra_options.skip_redo == 0 && hydra_targets[target_no]->redo <= hydra_options.max_use * 2 && ((hydra_heads[head_no]->current_login_ptr != empty_login && hydra_heads[head_no]->current_pass_ptr != empty_login) || (hydra_heads[head_no]->current_login_ptr != NULL && hydra_heads[head_no]->current_pass_ptr != NULL))) {
        hydra_targets[target_no]->redo_login[hydra_targets[target_no]->redo] = hydra_heads[head_no]->current_login_ptr;
        hydra_targets[target_no]->redo_pass[hydra_targets[target_no]->redo] = hydra_heads[head_no]->current_pass_ptr;
        hydra_targets[target_no]->redo++;
        total_redo_count++;
        if (debug)
          printf("[DEBUG] - will be retried at the end: ip %s - login %s - "
                 "pass %s - child %d\n",
                 hydra_targets[target_no]->target, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, head_no);
        hydra_heads[head_no]->current_login_ptr = empty_login;
        hydra_heads[head_no]->current_pass_ptr = empty_login;
      }
      if (hydra_targets[target_no]->fail_count >= MAXFAIL + hydra_options.tasks * hydra_targets[target_no]->ok) {
        if (hydra_targets[target_no]->done == TARGET_ACTIVE && hydra_options.max_use <= hydra_targets[target_no]->failed) {
          if (hydra_targets[target_no]->ok == 1)
            hydra_targets[target_no]->done = TARGET_ERROR; // mark target as done by errors
          else
            hydra_targets[target_no]->done = TARGET_UNRESOLVED; // mark target as done by unable to connect
          hydra_brains.finished++;
          fprintf(stderr,
                  "[ERROR] Too many connect errors to target, disabling "
                  "%s://%s%s%s:%d\n",
                  hydra_options.service, hydra_targets[target_no]->ip[0] == 16 && strchr(hydra_targets[target_no]->target, ':') != NULL ? "[" : "", hydra_targets[target_no]->target, hydra_targets[target_no]->ip[0] == 16 && strchr(hydra_targets[target_no]->target, ':') != NULL ? "]" : "", hydra_targets[target_no]->port);
        } else {
          hydra_targets[target_no]->failed++;
        }
        if (hydra_brains.targets <= hydra_brains.finished)
          hydra_kill_head(head_no, 1, 0);
        else
          hydra_kill_head(head_no, 1, 2);
      }
      // we keep the last one alive as long as it make sense
    } else {
      // we need to put this in a list, otherwise we fail one login+pw test
      if (hydra_targets[target_no]->done == TARGET_ACTIVE && hydra_options.skip_redo == 0 && hydra_targets[target_no]->redo <= hydra_options.max_use * 2 && ((hydra_heads[head_no]->current_login_ptr != empty_login && hydra_heads[head_no]->current_pass_ptr != empty_login) || (hydra_heads[head_no]->current_login_ptr != NULL && hydra_heads[head_no]->current_pass_ptr != NULL))) {
        hydra_targets[target_no]->redo_login[hydra_targets[target_no]->redo] = hydra_heads[head_no]->current_login_ptr;
        hydra_targets[target_no]->redo_pass[hydra_targets[target_no]->redo] = hydra_heads[head_no]->current_pass_ptr;
        hydra_targets[target_no]->redo++;
        total_redo_count++;
        if (debug)
          printf("[DEBUG] - will be retried at the end: ip %s - login %s - "
                 "pass %s - child %d\n",
                 hydra_targets[target_no]->target, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, head_no);
        hydra_heads[head_no]->current_login_ptr = empty_login;
        hydra_heads[head_no]->current_pass_ptr = empty_login;
      }
      /*
            hydra_targets[target_no]->fail_count--;
            if (k < 5 && hydra_targets[target_no]->ok)
              hydra_targets[target_no]->fail_count--;
            if (k == 2 && hydra_targets[target_no]->ok)
              hydra_targets[target_no]->fail_count--;
      */
      if (hydra_brains.targets <= hydra_brains.finished)
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

char *hydra_reverse_login(int32_t head_no, char *login) {
  int32_t i, j;
  char *start, *pos;
  unsigned char keep;

  if (login == NULL || (j = strlen(login)) < 1)
    return empty_login;

  if (j > 248)
    j = 248;

  for (i = 0; i < j; i++)
    hydra_heads[head_no]->reverse[i] = login[j - (i + 1)];
  hydra_heads[head_no]->reverse[j] = 0;

  // UTF stuff now
  start = hydra_heads[head_no]->reverse;
  pos = start + j;

  while (start < --pos) {
    switch ((*pos & 0xF0) >> 4) {
    case 0xF: /* U+010000-U+10FFFF: four bytes. */
      keep = *pos;
      *pos = *(pos - 3);
      *(pos - 3) = keep;
      keep = *(pos - 1);
      *(pos - 1) = *(pos - 2);
      *(pos - 2) = keep;
      pos -= 3;
      break;
    case 0xE: /* U+000800-U+00FFFF: three bytes. */
      keep = *pos;
      *pos = *(pos - 2);
      *(pos - 2) = keep;
      pos -= 2;
      break;
    case 0xC: /* fall-through */
    case 0xD: /* U+000080-U+0007FF: two bytes. */
      keep = *pos;
      *pos = *(pos - 1);
      *(pos - 1) = keep;
      pos--;
      break;
    }
  }

  return hydra_heads[head_no]->reverse;
}

int32_t hydra_send_next_pair(int32_t target_no, int32_t head_no) {
  // variables moved to save stack
  snpdone = 0;
  snp_is_redo = 0;
  snpdont = 0;
  loop_cnt++;
  if (hydra_heads[head_no]->redo == 1 && hydra_heads[head_no]->current_login_ptr != NULL && hydra_heads[head_no]->current_pass_ptr != NULL) {
    hydra_heads[head_no]->redo = 0;
    snp_is_redo = 1;
    snpdone = 1;
  } else {
    if (hydra_targets[target_no]->sent >= hydra_brains.todo + hydra_targets[target_no]->redo) {
      if (hydra_targets[target_no]->done == TARGET_ACTIVE) {
        hydra_targets[target_no]->done = TARGET_FINISHED;
        hydra_brains.finished++;
        if (verbose)
          printf("[STATUS] attack finished for %s (waiting for children to "
                 "complete tests)\n",
                 hydra_targets[target_no]->target);
      }
      return -1;
    }
  }

  if (debug)
    printf("[DEBUG] send_next_pair_init target %d, head %d, redo %d, "
           "redo_state %d, pass_state %d. loop_mode %d, curlogin %s, curpass "
           "%s, tlogin %s, tpass %s, logincnt %" hPRIu64 "/%" hPRIu64 ", passcnt %" hPRIu64 "/%" hPRIu64 ", loop_cnt %d\n",
           target_no, head_no, hydra_targets[target_no]->redo, hydra_targets[target_no]->redo_state, hydra_targets[target_no]->pass_state, hydra_options.loop_mode, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, hydra_targets[target_no]->login_ptr, hydra_targets[target_no]->pass_ptr, hydra_targets[target_no]->login_no, hydra_brains.countlogin, hydra_targets[target_no]->pass_no, hydra_brains.countpass, loop_cnt);

  if (loop_cnt > (hydra_brains.countlogin * 2) + 1 && loop_cnt > (hydra_brains.countpass * 2) + 1) {
    if (debug)
      printf("[DEBUG] too many loops in send_next_pair, returning -1 (loop_cnt "
             "%d, sent %" hPRIu64 ", todo %" hPRIu64 ")\n",
             loop_cnt, hydra_targets[target_no]->sent, hydra_brains.todo);
    return -1;
  }

  if (hydra_heads[head_no]->redo == 1 && hydra_heads[head_no]->current_login_ptr != NULL && hydra_heads[head_no]->current_pass_ptr != NULL) {
    hydra_heads[head_no]->redo = 0;
    snp_is_redo = 1;
    snpdone = 1;
  } else {
    if (debug && (hydra_heads[head_no]->current_login_ptr != NULL || hydra_heads[head_no]->current_pass_ptr != NULL))
      printf("[COMPLETED] target %s - login \"%s\" - pass \"%s\" - child %d - "
             "%" hPRIu64 " of %" hPRIu64 "\n",
             hydra_targets[target_no]->target, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, head_no, hydra_targets[target_no]->sent, hydra_brains.todo + hydra_targets[target_no]->redo);
    // hydra_heads[head_no]->redo = 0;
    if (hydra_targets[target_no]->redo_state > 0) {
      if (hydra_targets[target_no]->redo_state <= hydra_targets[target_no]->redo) {
        hydra_heads[head_no]->current_pass_ptr = hydra_targets[target_no]->redo_pass[hydra_targets[target_no]->redo_state - 1];
        hydra_heads[head_no]->current_login_ptr = hydra_targets[target_no]->redo_login[hydra_targets[target_no]->redo_state - 1];
        hydra_targets[target_no]->redo_state++;
        snpdone = 1;
      } else {
        // if a pair does not complete after this point it is lost
        if (hydra_targets[target_no]->done == TARGET_ACTIVE) {
          hydra_targets[target_no]->done = TARGET_FINISHED;
          hydra_brains.finished++;
          if (verbose)
            printf("[STATUS] attack finished for %s (waiting for children to "
                   "complete tests)\n",
                   hydra_targets[target_no]->target);
        }
        loop_cnt = 0;
        return -1;
      }
    } else { // normale state, no redo
      if (hydra_targets[target_no]->done != TARGET_ACTIVE) {
        loop_cnt = 0;
        return -1; // head will be disabled by main while()
      }
      if (hydra_options.loop_mode == 0) { // one user after another
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
            // small check that there is a login name (could also be emtpy) and
            // if we already tried empty password it would be a double
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
            // small check that there is a login name (could also be emtpy) and
            // if we already tried empty password it would be a double
            if (hydra_options.try_password_reverse_login) {
              if ((hydra_options.try_password_same_as_login == 0 || strcmp(hydra_targets[target_no]->login_ptr, hydra_reverse_login(head_no, hydra_heads[head_no]->current_login_ptr)) != 0) && (hydra_options.try_null_password == 0 || (hydra_targets[target_no]->login_ptr != NULL && strlen(hydra_targets[target_no]->login_ptr) > 0))) {
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
            if (check_flag(hydra_options.mode, MODE_COLON_FILE)) { // colon mode
              hydra_heads[head_no]->current_login_ptr = hydra_targets[target_no]->login_ptr;
              hydra_heads[head_no]->current_pass_ptr = hydra_targets[target_no]->pass_ptr;
              hydra_targets[target_no]->login_no++;
              snpdone = 1;
              hydra_targets[target_no]->login_ptr = hydra_targets[target_no]->pass_ptr;
              // hydra_targets[target_no]->login_ptr++;
              while (*hydra_targets[target_no]->login_ptr != 0)
                hydra_targets[target_no]->login_ptr++;
              hydra_targets[target_no]->login_ptr++;
              hydra_targets[target_no]->pass_ptr = hydra_targets[target_no]->login_ptr;
              // hydra_targets[target_no]->pass_ptr++;
              while (*hydra_targets[target_no]->pass_ptr != 0)
                hydra_targets[target_no]->pass_ptr++;
              hydra_targets[target_no]->pass_ptr++;
              if (strcmp(hydra_targets[target_no]->login_ptr, hydra_heads[head_no]->current_login_ptr) != 0)
                hydra_targets[target_no]->pass_state = 0;
              if ((hydra_options.try_password_same_as_login && strcmp(hydra_heads[head_no]->current_pass_ptr, hydra_heads[head_no]->current_login_ptr) == 0) || (hydra_options.try_null_password && strlen(hydra_heads[head_no]->current_pass_ptr) == 0) || (hydra_options.try_password_reverse_login && strcmp(hydra_heads[head_no]->current_pass_ptr, hydra_reverse_login(head_no, hydra_heads[head_no]->current_login_ptr)) == 0)) {
                hydra_brains.sent++;
                hydra_targets[target_no]->sent++;
                if (debug)
                  printf("[DEBUG] double detected (-C)\n");
                return hydra_send_next_pair(target_no, head_no); // little trick to keep the code small
              }
            } else { // standard -l -L -p -P mode
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
              if ((hydra_options.try_password_same_as_login && strcmp(hydra_heads[head_no]->current_pass_ptr, hydra_heads[head_no]->current_login_ptr) == 0) || (hydra_options.try_null_password && strlen(hydra_heads[head_no]->current_pass_ptr) == 0) || (hydra_options.try_password_reverse_login && strcmp(hydra_heads[head_no]->current_pass_ptr, hydra_reverse_login(head_no, hydra_heads[head_no]->current_login_ptr)) == 0)) {
                hydra_brains.sent++;
                hydra_targets[target_no]->sent++;
                if (debug)
                  printf("[DEBUG] double detected (-Pp)\n");
                return hydra_send_next_pair(target_no, head_no); // little trick to keep the code small
              }
              snpdone = 1;
            }
          }
        }
      } else { // loop_mode == 1
        if (hydra_targets[target_no]->pass_no < hydra_brains.countpass) {
          hydra_heads[head_no]->current_login_ptr = hydra_targets[target_no]->login_ptr;
          if (hydra_targets[target_no]->pass_state == 0) {
            if (check_flag(hydra_options.mode, MODE_PASSWORD_BRUTE))
              hydra_heads[head_no]->current_pass_ptr = strdup(hydra_heads[head_no]->current_login_ptr);
            else
              hydra_heads[head_no]->current_pass_ptr = hydra_heads[head_no]->current_login_ptr;
          } else if (hydra_targets[target_no]->pass_state == 1) {
            if (check_flag(hydra_options.mode, MODE_PASSWORD_BRUTE))
              hydra_heads[head_no]->current_pass_ptr = strdup(empty_login);
            else
              hydra_heads[head_no]->current_pass_ptr = empty_login;
          } else if (hydra_targets[target_no]->pass_state == 2) {
            if (check_flag(hydra_options.mode, MODE_PASSWORD_BRUTE))
              hydra_heads[head_no]->current_pass_ptr = strdup(hydra_reverse_login(head_no, hydra_heads[head_no]->current_login_ptr));
            else
              hydra_heads[head_no]->current_pass_ptr = hydra_reverse_login(head_no, hydra_heads[head_no]->current_login_ptr);
          } else {
            if (hydra_options.bfg && hydra_targets[target_no]->pass_state == 3 && hydra_heads[head_no]->current_pass_ptr != NULL && strlen(hydra_heads[head_no]->current_pass_ptr) > 0 && hydra_heads[head_no]->current_pass_ptr != hydra_heads[head_no]->current_login_ptr)
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
                if (check_flag(hydra_options.mode, MODE_PASSWORD_BRUTE)) {
#ifndef HAVE_MATH_H
                  sleep(1);
#else
                  hydra_targets[target_no]->pass_ptr = bf_next();
                  if (debug)
                    printf("[DEBUG] bfg new password for next child: %s\n", hydra_targets[target_no]->pass_ptr);
#endif
                } else { // -p -P mode
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
          } else {
            hydra_targets[target_no]->login_ptr++;
            while (*hydra_targets[target_no]->login_ptr != 0)
              hydra_targets[target_no]->login_ptr++;
            hydra_targets[target_no]->login_ptr++;
          }
          if (hydra_targets[target_no]->pass_state == 3 && snpdont == 0) {
            if ((hydra_options.try_null_password && strlen(hydra_heads[head_no]->current_pass_ptr) < 1) || (hydra_options.try_password_same_as_login && strcmp(hydra_heads[head_no]->current_pass_ptr, hydra_heads[head_no]->current_login_ptr) == 0) || (hydra_options.try_password_reverse_login && strcmp(hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr) == 0)) {
              hydra_brains.sent++;
              hydra_targets[target_no]->sent++;
              if (debug)
                printf("[DEBUG] double detected (1)\n");
              return hydra_send_next_pair(target_no, head_no); // little trick to keep the code small
            }
          }
        }
      }
    }

    if (debug)
      printf("[DEBUG] send_next_pair_mid done %d, pass_state %d, clogin %s, "
             "cpass %s, tlogin %s, tpass %s, redo %d\n",
             snpdone, hydra_targets[target_no]->pass_state, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, hydra_targets[target_no]->login_ptr, hydra_targets[target_no]->pass_ptr, hydra_targets[target_no]->redo);

    // no pair? then we go for redo state
    if (!snpdone && hydra_targets[target_no]->redo_state == 0 && hydra_targets[target_no]->redo > 0) {
      if (debug)
        printf("[DEBUG] Entering redo_state\n");
      hydra_targets[target_no]->redo_state++;
      return hydra_send_next_pair(target_no, head_no); // little trick to keep the code small
    }
  }

  if (!snpdone || hydra_targets[target_no]->skipcnt >= hydra_brains.countlogin) {
    fck = write(hydra_heads[head_no]->sp[0], HYDRA_EXIT, sizeof(HYDRA_EXIT));
    if (hydra_targets[target_no]->use_count <= 1) {
      if (hydra_targets[target_no]->done == TARGET_ACTIVE) {
        hydra_targets[target_no]->done = TARGET_FINISHED;
        hydra_brains.finished++;
        if (verbose)
          printf("[STATUS] attack finished for %s (waiting for children to "
                 "complete tests)\n",
                 hydra_targets[target_no]->target);
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
        if (!check_flag(hydra_options.mode, MODE_COLON_FILE) && hydra_options.loop_mode == 0 && hydra_targets[target_no]->pass_no > 0) { // -l -P (not! -u)
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
        return hydra_send_next_pair(target_no, head_no); // little trick to keep the code small
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
      printf("[DEBUG] send_next_pair_redo done %d, pass_state %d, clogin %s, "
             "cpass %s, tlogin %s, tpass %s, is_redo %d\n",
             snpdone, hydra_targets[target_no]->pass_state, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, hydra_targets[target_no]->login_ptr, hydra_targets[target_no]->pass_ptr, snp_is_redo);
    // hydra_dump_data(snpbuf, snpbuflen, "SENT");
    fck = write(hydra_heads[head_no]->sp[0], snpbuf, snpbuflen);
    if (fck < snpbuflen) {
      if (verbose)
        fprintf(stderr, "[ERROR] can not write to child %d, restarting it ...\n", head_no);
      hydra_increase_fail_count(target_no, head_no);
      loop_cnt = 0;
      return 0; // not prevent disabling it, if its needed its already done in
                // the above line
    }
    if (debug || hydra_options.showAttempt) {
      printf("[%sATTEMPT] target %s - login \"%s\" - pass \"%s\" - %" hPRIu64 " of %" hPRIu64 " [child %d] (%d/%d)\n",
             hydra_targets[target_no]->redo_state ? "REDO-"
             : snp_is_redo                        ? "RE-"
                                                  : "",
             hydra_targets[target_no]->target, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, hydra_targets[target_no]->sent, hydra_brains.todo + hydra_targets[target_no]->redo, head_no, hydra_targets[target_no]->redo_state ? hydra_targets[target_no]->redo_state - 1 : 0, hydra_targets[target_no]->redo);
    }
    loop_cnt = 0;
    return 0;
  }
  loop_cnt = 0;
  return -1;
}

void hydra_skip_user(int32_t target_no, char *username) {
  int32_t i;

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
  if (hydra_options.loop_mode == 0 && !check_flag(hydra_options.mode, MODE_COLON_FILE)) {
    if (strcmp(username, hydra_targets[target_no]->login_ptr) == 0) {
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

int32_t hydra_check_for_exit_condition() {
  int32_t i, k = 0;

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
      if (hydra_heads[i]->active >= HEAD_UNUSED)
        k = 1;
    if (k == 0) {
      fprintf(stderr, "[ERROR] all children were disabled due too many "
                      "connection errors\n");
      return -1;
    }
  }
  return 0;
}

int32_t hydra_select_target() {
  int32_t target_no = -1, i, j = -1000;

  for (i = 0; i < hydra_brains.targets; i++)
    if (hydra_targets[i]->use_count < hydra_options.tasks && hydra_targets[i]->done == TARGET_ACTIVE)
      if (j < hydra_options.tasks - hydra_targets[i]->failed - hydra_targets[i]->use_count) {
        target_no = i;
        j = hydra_options.tasks - hydra_targets[i]->failed - hydra_targets[i]->use_count;
      }
  return target_no;
}

void process_proxy_line(int32_t type, char *string) {
  char *type_string = string, *target_string, *port_string, *auth_string = NULL, *device_string = NULL, *sep;
  int32_t port;
  struct addrinfo hints, *res, *p;
  struct sockaddr_in6 *ipv6 = NULL;
  struct sockaddr_in *ipv4 = NULL;

  if (string == NULL || string[0] == 0 || string[0] == '#')
    return;
  while (*string == ' ' || *string == '\t')
    string++;
  if (*string == '#' || *string == ';' || strlen(string) < 5)
    return;
  if (string[strlen(string) - 1] == '\n')
    string[strlen(string) - 1] = 0;
  if (string[strlen(string) - 1] == '\r')
    string[strlen(string) - 1] = 0;
  if (proxy_count > MAX_PROXY_COUNT) {
    fprintf(stderr, "[WARNING] maximum amount of proxies loaded, ignoring this entry: %s\n", string);
    return;
  }
  if (debug)
    printf("[DEBUG] proxy line: %s\n", string);
  if ((sep = strstr(string, "://")) == NULL) {
    fprintf(stderr, "[WARNING] invalid proxy definition: %s (ignored)\n", string);
    return;
  }
  *sep = 0;
  target_string = sep + 3;
  if ((sep = strchr(target_string, '@')) != NULL) {
    auth_string = target_string;
    *sep = 0;
    target_string = sep + 1;
    if (strchr(auth_string, ':') == NULL) {
      fprintf(stderr,
              "[WARNING] %s has an invalid authentication definition %s, must "
              "be in the format login:pass, entry ignored\n",
              target_string, auth_string);
      return;
    }
  }
  if ((sep = strchr(target_string, ':')) != NULL) {
    *sep = 0;
    port_string = sep + 1;
    if ((sep = strchr(port_string, '%')) != NULL) {
      *sep = 0;
      device_string = sep + 1;
    }
    if ((sep = strchr(port_string, '/')) != NULL)
      *sep = 0;
    port = atoi(port_string);
    if (port < 1 || port > 65535) {
      fprintf(stderr, "[WARNING] %s has an invalid port definition %d, entry ignored\n", target_string, port);
      return;
    }
  } else {
    fprintf(stderr,
            "[WARNING] %s has not port definition which is required, entry "
            "ignored\n",
            target_string);
    return;
  }

  if (use_proxy == 1 && strcmp(type_string, "http") != 0) {
    fprintf(stderr,
            "[WARNING] %s:// is an invalid type, must be http:// if you use "
            "HYDRA_PROXY_HTTP, entry ignored\n",
            type_string);
    return;
  }
  if (use_proxy == 2 && strcmp(type_string, "connect") != 0 && strcmp(type_string, "socks4") != 0 && strcmp(type_string, "socks5") != 0) {
    fprintf(stderr,
            "[WARNING] %s:// is an invalid type, must be connect://, socks4:// "
            "or socks5:// if you use HYDRA_PROXY, entry ignored\n",
            type_string);
    return;
  }

  memset(&hints, 0, sizeof hints);
  if (getaddrinfo(target_string, NULL, &hints, &res) != 0) {
    fprintf(stderr, "[ERROR] could not resolve proxy target %s, entry ignored\n", target_string);
    return;
  }

  for (p = res; p != NULL; p = p->ai_next) {
#ifdef AF_INET6
    if (p->ai_family == AF_INET6) {
      if (ipv6 == NULL || memcmp((char *)&ipv6->sin6_addr, fe80, 2) == 0)
        ipv6 = (struct sockaddr_in6 *)p->ai_addr;
    } else
#endif
        if (p->ai_family == AF_INET) {
      if (ipv4 == NULL)
        ipv4 = (struct sockaddr_in *)p->ai_addr;
    }
  }
  freeaddrinfo(res);

  // now fill the stuff
#ifdef AF_INET6
  if (ipv6 != NULL && (ipv4 == NULL || prefer_ipv6)) {
    if (memcmp(proxy_string_ip[proxy_count] + 1, fe80, 2) == 0 && device_string == NULL) {
      fprintf(stderr,
              "[WARNING] The proxy address %s is a link local address, link "
              "local addresses require the interface being defined like this: "
              "fe80::1%%eth0, entry ignored\n",
              target_string);
      return;
    }
    proxy_string_ip[proxy_count][0] = 16;
    memcpy(proxy_string_ip[proxy_count] + 1, (char *)&ipv6->sin6_addr, 16);
    if (device_string != NULL && strlen(device_string) <= 16)
      strcpy(proxy_string_ip[proxy_count] + 17, device_string);
  } else
#endif
      if (ipv4 != NULL) {
    proxy_string_ip[proxy_count][0] = 4;
    memcpy(proxy_string_ip[proxy_count] + 1, (char *)&ipv4->sin_addr, 4);
  } else {
    fprintf(stderr, "[WARNING] Could not resolve proxy address: %s, entry ignored\n", target_string);
    return;
  }
  if (auth_string != NULL) {
    if ((proxy_authentication[proxy_count] = malloc(strlen(auth_string) * 2 + 8)) == NULL) {
      perror("malloc");
      return;
    }
    strcpy(proxy_authentication[proxy_count], auth_string);
    if (strncmp(type_string, "socks", 5) != 0) // so it is web
      hydra_tobase64((unsigned char *)proxy_authentication[proxy_count], strlen(proxy_authentication[proxy_count]), strlen(auth_string) * 2 + 8);
  } else
    proxy_authentication[proxy_count] = NULL;
  strcpy(proxy_string_type[proxy_count], type_string);
  proxy_string_port[proxy_count] = port;

  if (debug)
    printf("[DEBUG] count %d type %s target %s port %d auth %s\n", proxy_count, proxy_string_type[proxy_count], target_string, proxy_string_port[proxy_count], proxy_authentication[proxy_count]);
  proxy_count++;
}

int main(int argc, char *argv[]) {
  char *proxy_string = NULL, *device = NULL, *memcheck;
  char *outfile_format_tmp;
  FILE *lfp = NULL, *pfp = NULL, *cfp = NULL, *ifp = NULL, *rfp = NULL, *proxyfp;
  size_t countinfile = 1, sizeinfile = 0;
  uint64_t math2;
  int32_t i = 0, j = 0, k, error = 0, modusage = 0, ignore_restore = 0, do_switch;
  int32_t head_no = 0, target_no = 0, exit_condition = 0, readres;
  time_t starttime, elapsed_status, elapsed_restore, status_print = 59, tmp_time;
  char *tmpptr, *tmpptr2;
  char rc, buf[MAXBUF];
  time_t last_attempt = 0;
  fd_set fdreadheads;
  int32_t max_fd;
  struct addrinfo hints, *res, *p;
  struct sockaddr_in6 *ipv6 = NULL;
  struct sockaddr_in *ipv4 = NULL;

  printf("%s %s (c) 2023 by %s & %s - Please do not use in military or secret "
         "service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).\n\n",
         PROGRAM, VERSION, AUTHOR, AUTHOR2);
#ifndef LIBAFP
  SERVICES = hydra_string_replace(SERVICES, "afp ", "");
  strcat(unsupported, "afp ");
#endif
#ifndef LIBFIREBIRD
  SERVICES = hydra_string_replace(SERVICES, "firebird ", "");
  strcat(unsupported, "firebird ");
#endif
#ifndef LIBMCACHED
  SERVICES = hydra_string_replace(SERVICES, "memcached ", "");
  strcat(unsupported, "memcached ");
#endif
#ifndef LIBMONGODB
  SERVICES = hydra_string_replace(SERVICES, "mongodb ", "");
  strcat(unsupported, "mongodb ");
#endif
#ifndef LIBMYSQLCLIENT
  SERVICES = hydra_string_replace(SERVICES, "mysql ", "mysql(v4) ");
  strcat(unsupported, "mysql5 ");
#endif
#ifndef LIBNCP
  SERVICES = hydra_string_replace(SERVICES, "ncp ", "");
  strcat(unsupported, "ncp ");
#endif
#ifndef LIBORACLE
  SERVICES = hydra_string_replace(SERVICES, "oracle ", "");
  strcat(unsupported, "oracle ");
#endif
#ifndef LIBPOSTGRES
  SERVICES = hydra_string_replace(SERVICES, "postgres ", "");
  strcat(unsupported, "postgres ");
#endif
#ifndef HAVE_GCRYPT
  SERVICES = hydra_string_replace(SERVICES, "radmin2 ", "");
  strcat(unsupported, "radmin2 ");
#endif
#ifndef LIBFREERDP
  SERVICES = hydra_string_replace(SERVICES, "rdp ", "");
  strcat(unsupported, "rdp ");
#endif
#ifndef LIBSAPR3
  SERVICES = hydra_string_replace(SERVICES, "sapr3 ", "");
  strcat(unsupported, "sapr3 ");
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
#if !defined(LIBSMBCLIENT)
  SERVICES = hydra_string_replace(SERVICES, "smb2 ", "");
  strcat(unsupported, "smb2 ");
#endif

#ifndef LIBOPENSSL
  // for ftps
  SERVICES = hydra_string_replace(SERVICES, "ftp[s]", "ftp");
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

  (void)setvbuf(stdout, NULL, _IONBF, 0);
  (void)setvbuf(stderr, NULL, _IONBF, 0);
  // set defaults
  memset(&hydra_options, 0, sizeof(hydra_options));
  memset(&hydra_brains, 0, sizeof(hydra_brains));
  prg = argv[0];
  hydra_options.debug = debug = 0;
  hydra_options.verbose = verbose = 0;
  found = 0;
  use_proxy = 0;
  proxy_count = 0;
  selected_proxy = -1;
  proxy_string_ip[0][0] = 0;
  proxy_string_port[0] = 0;
  strcpy(proxy_string_type[0], "connect");
  proxy_authentication[0] = cmdlinetarget = NULL;
  hydra_options.login = NULL;
  hydra_options.loginfile = NULL;
  hydra_options.pass = NULL;
  hydra_options.passfile = NULL;
  hydra_options.tasks = TASKS;
  hydra_options.max_use = MAXTASKS;
  hydra_options.outfile_format = FORMAT_PLAIN_TEXT;
  hydra_brains.ofp = stdout;
  hydra_brains.targets = 1;
  hydra_options.waittime = waittime = WAITTIME;
  bf_options.disable_symbols = 0;

  // command line processing
  if (argc > 1 && strncmp(argv[1], "-h", 2) == 0)
    help(1);
  if (argc < 2)
    help(0);
  while ((i = getopt(argc, argv, "hIq64Rrde:vVl:fFg:L:p:OP:o:b:M:C:t:T:m:w:W:s:SUux:yc:K")) >= 0) {
    switch (i) {
    case 'h':
      help(1);
      break;
    case 'q':
      quiet = 1;
      break;
    case 'K':
      hydra_options.skip_redo = 1;
      break;
    case 'O':
      old_ssl = 1;
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
      hydra_restore_read();
      break;
    case 'r':
      fprintf(stderr, "Warning: the option -r has been removed.\n");
      break;
    case 'I':
      ignore_restore = 1; // this is not to be saved in hydra_options!
      break;
    case 'd':
      hydra_options.debug = ++debug;
      ++verbose;
      break;
    case 'e':
      i = 0;
      while (i < strlen(optarg)) {
        switch (optarg[i]) {
        case 'r':
          hydra_options.try_password_reverse_login = 1;
          hydra_options.mode = hydra_options.mode | MODE_PASSWORD_REVERSE;
          break;
        case 'n':
          hydra_options.try_null_password = 1;
          hydra_options.mode = hydra_options.mode | MODE_PASSWORD_NULL;
          break;
        case 's':
          hydra_options.try_password_same_as_login = 1;
          hydra_options.mode = hydra_options.mode | MODE_PASSWORD_SAME;
          break;
        default:
          fprintf(stderr,
                  "[ERROR] unknown mode %c for option -e, only supporting "
                  "\"n\", \"s\" and \"r\"\n",
                  optarg[i]);
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
      hydra_options.mode = hydra_options.mode | MODE_LOGIN_LIST;
      break;
    case 'p':
      hydra_options.pass = optarg;
      break;
    case 'P':
      hydra_options.passfile = optarg;
      hydra_options.mode = hydra_options.mode | MODE_PASSWORD_LIST;
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
    case 'b':
      outfile_format_tmp = optarg;
      if (strcasecmp(outfile_format_tmp, "text") == 0)
        hydra_options.outfile_format = FORMAT_PLAIN_TEXT;
      else if (strcasecmp(outfile_format_tmp, "json") == 0) // latest json formatting.
        hydra_options.outfile_format = FORMAT_JSONV1;
      else if (strcasecmp(outfile_format_tmp, "jsonv1") == 0)
        hydra_options.outfile_format = FORMAT_JSONV1;
      else {
        fprintf(stderr, "[ERROR] Output file format must be (text, json, jsonv1)\n");
        exit(-1);
      }
      //      colored_output = 0;
      break;
    case 'M':
      hydra_options.infile_ptr = optarg;
      break;
    case 'C':
      hydra_options.colonfile = optarg;
      hydra_options.mode = MODE_COLON_FILE;
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
        fprintf(stderr, "[WARNING] the waittime you set is low, this can "
                        "result in errornous results\n");
      break;
    case 'W':
      hydra_options.conwait = conwait = atoi(optarg);
      break;
    case 's':
      hydra_options.port = port = atoi(optarg);
      break;
    case 'c':
#ifdef MSG_PEEK
      hydra_options.time_next_attempt = atoi(optarg);
      if (hydra_options.time_next_attempt < 0) {
        fprintf(stderr, "[ERROR] -c option value can not be negative\n");
        exit(-1);
      }
#else
      fprintf(stderr, "[WARNING] -c option can not be used as your operating "
                      "system is missing the MSG_PEEK feature\n");
#endif
      break;
    case 'S':
#ifndef LIBOPENSSL
      fprintf(stderr, "[WARNING] hydra was compiled without SSL support. "
                      "Install openssl and recompile! Option ignored...\n");
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
      fprintf(stderr, "[ERROR] -x option is not available as math.h was not "
                      "found at compile time\n");
      exit(-1);
#else
      if (strcmp(optarg, "-h") == 0)
        help_bfg();
      bf_options.arg = optarg;
      hydra_options.bfg = 1;
      hydra_options.mode = hydra_options.mode | MODE_PASSWORD_BRUTE;
      hydra_options.loop_mode = 1;
      break;
#endif
    case 'y':
      bf_options.disable_symbols = 1;
      break;
    default:
      exit(-1);
    }
  }

  if (hydra_options.time_next_attempt > 0 && hydra_options.tasks != 1) {
    printf("[INFO] setting max tasks per host to 1 due to -c option usage\n");
    hydra_options.tasks = 1;
  }

  // check if output is redirected from the shell or in a file
  if (colored_output && !isatty(fileno(stdout)))
    colored_output = 0;

#ifdef LIBNCURSES
  // then check if the term is color enabled using ncurses lib
  if (colored_output) {
    if (!setupterm(NULL, 1, NULL) && (tigetnum("colors") <= 0)) {
      colored_output = 0;
    }
    if (cur_term) {
      del_curterm(cur_term);
    }
  }
#else
  // don't want border line effect so disabling color output
  // if we are not sure about the term
  colored_output = 0;
#endif

  if (debug)
    printf("[DEBUG] Output color flag is %d\n", colored_output);

  if (hydra_options.restore && argc > 2 + debug + verbose)
    fprintf(stderr, "[WARNING] options after -R are now honored (since v8.6)\n");
  //    bail("no option may be supplied together with -R");

  printf("%s (%s) starting at %s\n", PROGRAM, RESOURCE, hydra_build_time());
  if (debug) {
    printf("[DEBUG] cmdline: ");
    for (i = 0; i < argc; i++)
      printf("%s ", argv[i]);
    printf("\n");
  }
  if (hydra_options.tasks > 1 && hydra_options.time_next_attempt)
    fprintf(stderr, "[WARNING] when using the -c option, you should also set "
                    "the task per target to one (-t 1)\n");
  if (hydra_options.login != NULL && hydra_options.loginfile != NULL)
    bail("You can only use -L OR -l, not both\n");
  if (hydra_options.pass != NULL && hydra_options.passfile != NULL)
    bail("You can only use -P OR -p, not both\n");
  if (hydra_options.outfile_format != FORMAT_PLAIN_TEXT && hydra_options.outfile_ptr == NULL)
    fprintf(stderr, "[WARNING] output file format specified (-b) - but no "
                    "output file (-o)\n");

  if (hydra_options.restore) {
    //    hydra_restore_read();
    // stuff we have to copy from the non-restore part
    if (strncmp(hydra_options.service, "http-", 5) == 0) {
      if (getenv("HYDRA_PROXY_HTTP") && getenv("HYDRA_PROXY"))
        bail("Found HYDRA_PROXY_HTTP *and* HYDRA_PROXY environment variables - "
             "you can use only ONE for the service "
             "http-head/http-get/http-post!");
      if (getenv("HYDRA_PROXY_HTTP")) {
        printf("[INFO] Using HTTP Proxy: %s\n", getenv("HYDRA_PROXY_HTTP"));
        use_proxy = 1;
      }
    }
  } else { // normal mode, aka non-restore mode
    if (hydra_options.colonfile)
      hydra_options.loop_mode = 0; // just to be sure
    if (hydra_options.infile_ptr != NULL) {
      if (optind + 2 < argc)
        bail("The -M FILE option can not be used together with a host on the "
             "commandline");
      if (optind + 1 > argc)
        bail("You need to define a service to attack");
      if (optind + 2 == argc)
        fprintf(stderr, "[WARNING] With the -M FILE option you can not specify a server on "
                        "the commandline. Lets hope you did everything right!\n");
      hydra_options.server = NULL;
      hydra_options.service = argv[optind];
      if (optind + 2 == argc)
        hydra_options.miscptr = argv[optind + 1];
    } else if (optind + 2 != argc && optind + 3 != argc && optind < argc) {
      // check if targetdef follow syntax
      // <service-name>://<target>[:<port-number>][/<parameters>] or it's a
      // syntax error
      char *targetdef = strdup(argv[optind]);
      char *service_pos, *target_pos, *port_pos = NULL, *param_pos = NULL;
      cmdlinetarget = argv[optind];

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
          if ((param_pos = strchr(target_pos, ']')) == NULL)
            bail("no closing ']' found in target definition");
          *param_pos++ = 0;
          if (*param_pos == ':')
            port_pos = ++param_pos;
          if ((param_pos = strchr(param_pos, '/')) != NULL)
            *param_pos++ = 0;
        } else {
          port_pos = strchr(target_pos, ':');
          param_pos = strchr(target_pos, '/');
          if (port_pos != NULL && param_pos != NULL && port_pos > param_pos)
            port_pos = NULL;
          if (port_pos != NULL)
            *port_pos++ = 0;
          if (param_pos != NULL)
            *param_pos++ = 0;
          if (port_pos != NULL && strchr(port_pos, ':') != NULL) {
            if (prefer_ipv6)
              bail("Illegal IPv6 target definition must be written within '[' "
                   "']'");
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
          hydra_options.miscptr = strdup(param_pos);
        }
        // printf("target: %s  service: %s  port: %s  opt: %s\n", target_pos,
        // hydra_options.service, port_pos, param_pos);
        if (debug)
          printf("[DEBUG] opt:%d argc:%d mod:%s tgt:%s port:%u misc:%s\n", optind, argc, hydra_options.service, hydra_options.server, hydra_options.port, hydra_options.miscptr);
      } else {
        hydra_options.server = NULL;
        hydra_options.service = NULL;

        if (modusage) {
          hydra_options.service = targetdef;
        } else
          help(0);
      }
    } else {
      if (modusage && argv[optind] == NULL) {
        printf("[ERROR] you must supply a service name after the -U help "
               "switch\n");
        exit(-1);
      }
      if (argv[optind] == NULL || strstr(argv[optind], "://") != NULL) {
        printf("[ERROR] Invalid target definition!\n");
        printf("[ERROR] Either you use \"www.example.com module "
               "[optional-module-parameters]\" *or* you use the "
               "\"module://www.example.com/optional-module-parameters\" "
               "syntax!\n");
        exit(-1);
      }
      hydra_options.server = argv[optind];
      cmdlinetarget = argv[optind];
      hydra_options.service = argv[optind + 1];
      if (optind + 3 == argc)
        hydra_options.miscptr = argv[optind + 2];
    }

    if (getenv("HYDRA_PROXY_CONNECT"))
      fprintf(stderr, "[WARNING] The environment variable HYDRA_PROXY_CONNECT "
                      "is not used! Use HYDRA_PROXY instead!\n");

    // wrong option use patch
    if (hydra_options.ssl && (((strcmp(hydra_options.service, "smtp") == 0 || strcmp(hydra_options.service, "smtp-enum") == 0) && hydra_options.port != 465) || (strcmp(hydra_options.service, "pop3") == 0 && hydra_options.port != 995) || (strcmp(hydra_options.service, "imap") == 0 && hydra_options.port != 993)))
      fprintf(stderr, "[WARNING] you want to access SMTP/POP3/IMAP with SSL. Are you sure "
                      "you want to use direct SSL (-S) instead of STARTTLS (-m TLS)?\n");

    if (strcmp(hydra_options.service, "http") == 0 || strcmp(hydra_options.service, "https") == 0) {
      fprintf(stderr,
              "[ERROR] There is no service \"%s\", most likely you mean one of the "
              "many web modules, e.g. http-get or http-form-post. Read it up!\n",
              hydra_options.service);
      exit(-1);
    }

    if (strcmp(hydra_options.service, "pop3s") == 0 || strcmp(hydra_options.service, "smtps") == 0 || strcmp(hydra_options.service, "imaps") == 0 || strcmp(hydra_options.service, "telnets") == 0 || (strncmp(hydra_options.service, "ldap", 4) == 0 && hydra_options.service[strlen(hydra_options.service) - 1] == 's')) {
      hydra_options.ssl = 1;
      hydra_options.service[strlen(hydra_options.service) - 1] = 0;
    }

    if (getenv("HYDRA_PROXY_HTTP") || getenv("HYDRA_PROXY")) {
      if (strcmp(hydra_options.service, "afp") == 0 || strcmp(hydra_options.service, "firebird") == 0 || strncmp(hydra_options.service, "mysql", 5) == 0 || strcmp(hydra_options.service, "ncp") == 0 || strcmp(hydra_options.service, "oracle") == 0 || strcmp(hydra_options.service, "postgres") == 0 || strncmp(hydra_options.service, "ssh", 3) == 0 || strcmp(hydra_options.service, "sshkey") == 0 || strcmp(hydra_options.service, "svn") == 0 || strcmp(hydra_options.service, "sapr3") == 0 ||
          strcmp(hydra_options.service, "memcached") == 0 || strcmp(hydra_options.service, "mongodb") == 0) {
        fprintf(stderr, "[WARNING] module %s does not support HYDRA_PROXY* !\n", hydra_options.service);
        proxy_string = NULL;
      }
    }

    /* here start the services */

    if (strcmp(hydra_options.service, "ssl") == 0 || strcmp(hydra_options.service, "www") == 0 || strcmp(hydra_options.service, "http") == 0 || strcmp(hydra_options.service, "https") == 0) {
      fprintf(stderr, "[WARNING] The service http has been replaced with http-head and "
                      "http-get, using by default GET method. Same for https.\n");
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

    if (modusage == 1) {
      if (hydra_options.service == NULL) {
        printf("[ERROR] you must supply a service name after the -U help "
               "switch\n");
        exit(-1);
      }
      module_usage();
    }

    i = 0;
    if (strcmp(hydra_options.service, "telnet") == 0) {
      fprintf(stderr, "[WARNING] telnet is by its nature unreliable to analyze, if "
                      "possible better choose FTP, SSH, etc. if available\n");
      i = 1;
    }
    if (strcmp(hydra_options.service, "ftp") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "ftps") == 0) {
      fprintf(stderr, "[WARNING] you enabled ftp-SSL (auth tls) mode. If you want to "
                      "use direct SSL ftp, use -S and the ftp module instead.\n");
      i = 1;
    }
    if (strcmp(hydra_options.service, "pop3") == 0) {
      fprintf(stderr, "[INFO] several providers have implemented cracking protection, "
                      "check with a small wordlist first - and stay legal!\n");
      i = 1;
    }
    if (strcmp(hydra_options.service, "imap") == 0) {
      fprintf(stderr, "[INFO] several providers have implemented cracking protection, "
                      "check with a small wordlist first - and stay legal!\n");
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
      fprintf(stderr, "[WARNING] The icq module is not working with the modern "
                      "protocol version! (somebody else will need to fix this "
                      "as I don't care for icq)\n");
      i = 1;
    }
    if (strcmp(hydra_options.service, "memcached") == 0)
#ifdef LIBMCACHED
      i = 1;
#else
      bail("Compiled without LIBMCACHED support, module not available!");
#endif

    if (strcmp(hydra_options.service, "mongodb") == 0)
#ifdef LIBMONGODB
    {
      i = 1;
      if (hydra_options.miscptr == NULL || (strlen(hydra_options.miscptr) == 0))
        fprintf(stderr, "[INFO] The mongodb db wasn't passed so using admin by default\n");
    }
#else
      bail("Compiled without LIBMONGODB support, module not available!");
#endif

    if (strcmp(hydra_options.service, "mysql") == 0) {
      i = 1;
      if (hydra_options.tasks > 4) {
        fprintf(stderr, "[INFO] Reduced number of tasks to 4 (mysql does not "
                        "like many parallel connections)\n");
        hydra_options.tasks = 4;
      }
    }
    if (strcmp(hydra_options.service, "mssql") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "cobaltstrike") == 0)
      i = 2;
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
        fprintf(stderr, "[INFO] The CVS repository path wasn't passed so using "
                        "/root by default\n");
      }
    }
    if (strcmp(hydra_options.service, "svn") == 0) {
      i = 1;
      if (hydra_options.miscptr == NULL || (strlen(hydra_options.miscptr) == 0)) {
        fprintf(stderr, "[INFO] The SVN repository path wasn't passed so using "
                        "/trunk by default\n");
      }
    }
    if (strcmp(hydra_options.service, "ssh") == 0 || strcmp(hydra_options.service, "sshkey") == 0) {
      if (hydra_options.tasks > 8)
        fprintf(stderr, "[WARNING] Many SSH configurations limit the number of parallel "
                        "tasks, it is recommended to reduce the tasks: use -t 4\n");
#ifdef LIBSSH
      i = 1;
#else
      bail("Compiled without LIBSSH v0.4.x support, module is not available!");
#endif
    }
    if (strcmp(hydra_options.service, "smtp") == 0) {
      fprintf(stderr, "[INFO] several providers have implemented cracking protection, "
                      "check with a small wordlist first - and stay legal!\n");
      i = 1;
    }
    if (strcmp(hydra_options.service, "smtp-enum") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "teamspeak") == 0)
      i = 1;
    if ((strcmp(hydra_options.service, "smb") == 0) || (strcmp(hydra_options.service, "smbnt") == 0)) {
      if (hydra_options.tasks > 1) {
        fprintf(stderr, "[INFO] Reduced number of tasks to 1 (smb does not "
                        "like parallel connections)\n");
        hydra_options.tasks = 1;
      }
      if (hydra_options.login != NULL && (strchr(hydra_options.login, '\\') != NULL || strchr(hydra_options.login, '/') != NULL))
        fprintf(stderr, "[WARNING] potential windows domain specification found in "
                        "login. You must use the -m option to pass a domain.\n");
      i = 1;
    }
    if ((strcmp(hydra_options.service, "smb") == 0) || (strcmp(hydra_options.service, "smbnt") == 0)) {
#ifdef LIBOPENSSL
      if (hydra_options.tasks > 1) {
        fprintf(stderr, "[INFO] Reduced number of tasks to 1 (smb does not "
                        "like parallel connections)\n");
        hydra_options.tasks = 1;
      }
      i = 1;
#endif
    }
    if ((strcmp(hydra_options.service, "smb") == 0) || (strcmp(hydra_options.service, "smbnt") == 0) || (strcmp(hydra_options.service, "sip") == 0) || (strcmp(hydra_options.service, "oracle-listener") == 0) || (strcmp(hydra_options.service, "oracle-sid") == 0)) {
#ifndef LIBOPENSSL
      bail("Compiled without OPENSSL support, module not available!");
#endif
    }
    if (strcmp(hydra_options.service, "smb2") == 0) {
#if !defined(LIBSMBCLIENT)
      bail("Compiled without LIBSMBCLIENT support, module not available!");
#else
      if (hydra_options.login != NULL && (strchr(hydra_options.login, '\\') != NULL || strchr(hydra_options.login, '/') != NULL))
        fprintf(stderr, "[WARNING] potential windows domain specification found in "
                        "login. You must use the -m option to pass a domain.\n");
      if (hydra_options.miscptr == NULL || (strlen(hydra_options.miscptr) == 0)) {
        fprintf(stderr, "[WARNING] Workgroup was not specified, using \"WORKGROUP\"\n");
      }
      i = 1;
#endif
    }

    if (strcmp(hydra_options.service, "rdp") == 0) {
#ifndef LIBFREERDP
      bail("Compiled without FREERDP support, modules not available!");
#endif
    }
    if (strcmp(hydra_options.service, "pcnfs") == 0) {
      i = 1;
      if (port == 0)
        bail("You must set the port for pcnfs with -s (run \"rpcinfo -p %s\" "
             "and look for the pcnfs v2 UDP port)");
    }
    if (strcmp(hydra_options.service, "sapr3") == 0) {
#ifdef LIBSAPR3
      i = 1;
      if (port == PORT_SAPR3)
        bail("You must set the port for sapr3 with -s <port>, it should lie "
             "between 3200 and 3699.");
      if (port < 3200 || port > 3699)
        fprintf(stderr, "[WARNING] The port is not in the range 3200 to 3399 - "
                        "please ensure it is ok!\n");
      if (hydra_options.miscptr == NULL || atoi(hydra_options.miscptr) < 0 || atoi(hydra_options.miscptr) > 999 || !isdigit(hydra_options.miscptr[0]))
        bail("You must set the client ID (0-999) as an additional option or "
             "via -m");
#else
      bail("Compiled without LIBSAPR3 support, module not available!");
#endif
    }
    if (strcmp(hydra_options.service, "cisco") == 0) {
      i = 2;
      if (hydra_options.tasks > 4)
        fprintf(stderr, "[WARNING] you should set the number of parallel task "
                        "to 4 for cisco services.\n");
    }
    if (strcmp(hydra_options.service, "adam6500") == 0) {
      i = 2;
      fprintf(stderr, "[WARNING] the module adam6500 is work in progress! "
                      "please submit a pcap of a successful login as well as "
                      "false positives to vh@thc.org\n");
      if (hydra_options.tasks > 1)
        fprintf(stderr, "[WARNING] reset the number of parallel task to 1 for "
                        "adam6500 modbus authentication\n");
      hydra_options.tasks = 1;
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
        fprintf(stderr, "[WARNING] SNMPv1 and SNMPv2 do not support hash and "
                        "encryption, ignored\n");
      if ((j & 3) == 3) {
        fprintf(stderr, "[WARNING] SNMPv3 is still in beta state, use at own "
                        "risk and report problems\n");
        if (j >= 16)
          bail("The SNMPv3 module so far only support authentication "
               "(md5/sha), not yet encryption\n");
        if (hydra_options.colonfile == NULL && ((hydra_options.login == NULL && hydra_options.loginfile == NULL) || (hydra_options.pass == NULL && hydra_options.passfile == NULL && hydra_options.bfg == 0))) {
          if (j > 3) {
            fprintf(stderr, "[ERROR] you specified SNMPv3, defined hashing/encryption but "
                            "only gave one of login or password list. Either supply both "
                            "logins and passwords (this is what is usually used in "
                            "SNMPv3), or remove the hashing/encryption option (unusual)\n");
            exit(-1);
          }
          fprintf(stderr, "[WARNING] you specified SNMPv3 but gave no logins, "
                          "NoAuthNoPriv is assumed. This is an unusual case, "
                          "you should know what you are doing\n");
          tmpptr = malloc(strlen(hydra_options.miscptr) + 8);
          strcpy(tmpptr, hydra_options.miscptr);
          strcat(tmpptr, ":");
          strcat(tmpptr, "PLAIN");
          hydra_options.miscptr = tmpptr;
        } else {
          i = 1; // snmpv3 with login+pass mode
#ifndef LIBOPENSSL
          bail("hydra was not compiled with OPENSSL support, snmpv3 can only "
               "be used on NoAuthNoPriv mode (only logins, no passwords)!");
#endif
          printf("[INFO] Using %s SNMPv3 with %s authentication and %s privacy\n", j > 16 ? "AuthPriv" : "AuthNoPriv", (j & 8) == 8 ? "SHA" : "MD5", (j & 16) == 16 ? "DES" : (j > 16) ? "AES" : "no");
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
      bail("Please select ldap2 or ldap3 for simple authentication or "
           "ldap3-crammd5 or ldap3-digestmd5\n");
    }
    if (strcmp(hydra_options.service, "ldap2") == 0 || strcmp(hydra_options.service, "ldap3") == 0) {
      i = 1;
      if ((hydra_options.miscptr != NULL && hydra_options.login != NULL) || (hydra_options.miscptr != NULL && hydra_options.loginfile != NULL) || (hydra_options.login != NULL && hydra_options.loginfile != NULL))
        bail("you may only use one of -l, -L or -m\n");
      if (hydra_options.login == NULL && hydra_options.loginfile == NULL && hydra_options.miscptr == NULL)
        fprintf(stderr, "[WARNING] no DN to authenticate is defined, using DN "
                        "of null (use -m, -l or -L to define DNs)\n");
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
    if (strcmp(hydra_options.service, "rtsp") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "rpcap") == 0)
      i = 1;
    if (strcmp(hydra_options.service, "s7-300") == 0) {
      if (hydra_options.tasks > 8) {
        fprintf(stderr, "[INFO] Reduced number of tasks to 8 (the PLC does not "
                        "like more connections)\n");
        hydra_options.tasks = 8;
      }
      i = 2;
    }
    if (strcmp(hydra_options.service, "cisco-enable") == 0) {
      if (hydra_options.login != NULL || hydra_options.loginfile != NULL)
        i = 1; // login will be the initial Username: login, or line Password:
      else
        i = 2;
      if (hydra_options.miscptr == NULL)
        fprintf(stderr, "[WARNING] You did not supply the initial support to "
                        "the Cisco via -l, assuming direct console access\n");
      if (hydra_options.tasks > 4)
        fprintf(stderr, "[WARNING] you should set the number of parallel task "
                        "to 4 for cisco enable services.\n");
    }
    if (strcmp(hydra_options.service, "http-proxy-urlenum") == 0) {
      i = 4;
      hydra_options.pass = empty_login;
      if (hydra_options.miscptr == NULL) {
        fprintf(stderr, "[WARNING] You did not supply proxy credentials via "
                        "the optional parameter\n");
      }
      if (hydra_options.bfg || hydra_options.passfile != NULL)
        bail("the http-proxy-urlenum does not need the -p/-P or -x option");
    }
    if (strcmp(hydra_options.service, "vnc") == 0) {
      i = 2;
      if (hydra_options.tasks > 4)
        fprintf(stderr, "[WARNING] you should set the number of parallel task "
                        "to 4 for vnc services.\n");
    }
    if (strcmp(hydra_options.service, "https-head") == 0 || strcmp(hydra_options.service, "https-get") == 0 || strcmp(hydra_options.service, "https-post") == 0) {
#ifdef LIBOPENSSL
      i = 1;
      hydra_options.ssl = 1;
      if (strcmp(hydra_options.service, "https-head") == 0)
        strcpy(hydra_options.service, "http-head");
      else if (strcmp(hydra_options.service, "https-post") == 0)
        strcpy(hydra_options.service, "http-post");
      else
        strcpy(hydra_options.service, "http-get");
#else
      bail("Compiled without SSL support, module not available");
#endif
    }
    if (strcmp(hydra_options.service, "http-get") == 0 || strcmp(hydra_options.service, "http-head") == 0 || strcmp(hydra_options.service, "http-post") == 0) {
      i = 1;
      if (hydra_options.miscptr == NULL) {
        fprintf(stderr, "[WARNING] You must supply the web page as an "
                        "additional option or via -m, default path set to /\n");
        hydra_options.miscptr = malloc(2);
        hydra_options.miscptr = "/";
      }
      if (*hydra_options.miscptr != '/' && strstr(hydra_options.miscptr, "://") == NULL)
        bail("The web page you supplied must start with a \"/\", \"http://\" "
             "or \"https://\", e.g. \"/protected/login\"");
      if (getenv("HYDRA_PROXY_HTTP") && getenv("HYDRA_PROXY"))
        bail("Found HYDRA_PROXY_HTTP *and* HYDRA_PROXY environment variables - "
             "you can use only ONE for the service http-head/http-get!");
      if (getenv("HYDRA_PROXY_HTTP")) {
        printf("[INFO] Using HTTP Proxy: %s\n", getenv("HYDRA_PROXY_HTTP"));
        use_proxy = 1;
      }
      if (strcmp(hydra_options.service, "http-head") == 0)
        fprintf(stderr, "[WARNING] http-head auth does not work with every "
                        "server, better use http-get\n");
    }

    if (strcmp(hydra_options.service, "http-get-form") == 0 || strcmp(hydra_options.service, "http-post-form") == 0 || strcmp(hydra_options.service, "https-get-form") == 0 || strcmp(hydra_options.service, "https-post-form") == 0) {
      char bufferurl[6096 + 24], *url, *variables, *cond,
          *optional1; // 6096 comes from issue 192 on github. Extra 24 bytes for
                      // null padding.

      if (strncmp(hydra_options.service, "http-", 5) == 0) {
        i = 1;
      } else { // https
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
        fprintf(stderr, "[WARNING] You must supply the web page as an "
                        "additional option or via -m, default path set to /\n");
        hydra_options.miscptr = malloc(2);
        hydra_options.miscptr = "/";
      }
      // if (*hydra_options.miscptr != '/' && strstr(hydra_options.miscptr,
      // "://") == NULL)
      //  bail("The web page you supplied must start with a \"/\", \"http://\"
      //  or \"https://\", e.g. \"/protected/login\"");
      if (hydra_options.miscptr[0] != '/')
        bail("optional parameter must start with a '/' slash!\n");
      if (getenv("HYDRA_PROXY_HTTP") && getenv("HYDRA_PROXY"))
        bail("Found HYDRA_PROXY_HTTP *and* HYDRA_PROXY environment variables - "
             "you can use only ONE for the service http-head/http-get!");
      if (getenv("HYDRA_PROXY_HTTP")) {
        printf("[INFO] Using HTTP Proxy: %s\n", getenv("HYDRA_PROXY_HTTP"));
        use_proxy = 1;
      }
      if (strstr(hydra_options.miscptr, "\\:") != NULL) {
        fprintf(stderr, "[INFORMATION] escape sequence \\: detected in module "
                        "option, no parameter verification is performed.\n");
      } else {
        sprintf(bufferurl, "%.6000s", hydra_options.miscptr);
        url = strtok(bufferurl, ":");
        variables = strtok(NULL, ":");
        cond = strtok(NULL, ":");
        optional1 = strtok(NULL, "\n");
        if ((variables == NULL) || (strstr(variables, "^USER^") == NULL && strstr(variables, "^PASS^") == NULL && strstr(variables, "^USER64^") == NULL && strstr(variables, "^PASS64^") == NULL)) {
          fprintf(stderr,
                  "[ERROR] the variables argument needs at least the strings "
                  "^USER^, ^PASS^, ^USER64^ or ^PASS64^: %s\n",
                  STR_NULL(variables));
          exit(-1);
        }
        if ((url == NULL) || (cond == NULL)) {
          fprintf(stderr,
                  "[ERROR] Wrong syntax, requires three arguments separated by "
                  "a colon which may not be null: %s\n",
                  bufferurl);
          exit(-1);
        }
        while ((optional1 = strtok(NULL, ":")) != NULL) {
          if (optional1[1] != '=' && optional1[1] != ':' && optional1[1] != 0) {
            fprintf(stderr, "[ERROR] Wrong syntax of optional argument: %s\n", optional1);
            exit(-1);
          }

          switch (optional1[0]) {
          case 'C': // fall through
          case 'c':
            if (optional1[1] != '=' || optional1[2] != '/') {
              fprintf(stderr,
                      "[ERROR] Wrong syntax of parameter C, must look like "
                      "'C=/url/of/page', not http:// etc.: %s\n",
                      optional1);
              exit(-1);
            }
            break;
          case 'H': // fall through
          case 'h':
            if (optional1[1] != '=' || strtok(NULL, ":") == NULL) {
              fprintf(stderr,
                      "[ERROR] Wrong syntax of parameter H, must look like "
                      "'H=X-My-Header: MyValue', no http:// : %s\n",
                      optional1);
              exit(-1);
            }
            break;
          default:
            fprintf(stderr, "[ERROR] Unknown optional argument: %s\n", optional1);
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
        fprintf(stderr, "[WARNING] rdp servers often don't like many connections, use -t 1 "
                        "or -t 4 to reduce the number of parallel connections and -W 1 or "
                        "-W 3 to wait between connection to allow the server to recover\n");
      if (hydra_options.tasks > 4) {
        fprintf(stderr, "[INFO] Reduced number of tasks to 4 (rdp does not "
                        "like many parallel connections)\n");
        hydra_options.tasks = 4;
      }
      if (conwait == 0)
        hydra_options.conwait = conwait = 1;
      printf("[WARNING] the rdp module is experimental. Please test, report - "
             "and if possible, fix.\n");
      i = 1;
    }
    if (strcmp(hydra_options.service, "radmin2") == 0) {
#ifdef HAVE_GCRYPT
      i = 1;
#else
      bail("hydra was not compiled with gcrypt support, radmin2 module not "
           "available");
#endif
    }

    // ADD NEW SERVICES HERE

    if (i == 0) {
      fprintf(stderr, "[ERROR] Unknown service: %s\n", hydra_options.service);
      exit(-1);
    }
    if (port < 1 || port > 65535) {
      if ((port = hydra_lookup_port(hydra_options.service)) < 1) {
        fprintf(stderr, "[ERROR] No valid port set or no default port "
                        "available. Use the -s Option.\n");
        exit(-1);
      }
      hydra_options.port = port;
    }

    if (hydra_options.login == NULL && hydra_options.loginfile == NULL && hydra_options.colonfile == NULL)
      hydra_options.exit_found = 1;

    if (hydra_options.ssl == 0 && hydra_options.port == 443)
      fprintf(stderr, "[WARNING] you specified port 443 for attacking a http "
                      "service, however did not specify the -S ssl switch nor "
                      "used https-..., therefore using plain HTTP\n");

    if (hydra_options.loop_mode && hydra_options.colonfile != NULL)
      bail("The loop mode option (-u) works with all modes - except colon "
           "files (-C)\n");
    if (strncmp(hydra_options.service, "http-", strlen("http-")) != 0 && strcmp(hydra_options.service, "http-head") != 0 && getenv("HYDRA_PROXY_HTTP") != NULL)
      fprintf(stderr, "[WARNING] the HYDRA_PROXY_HTTP environment variable works only "
                      "with the http-head/http-get module, ignored...\n");
    if (i == 2) {
      if (hydra_options.colonfile != NULL || ((hydra_options.login != NULL || hydra_options.loginfile != NULL) && (hydra_options.pass != NULL || hydra_options.passfile != NULL || hydra_options.bfg > 0)))
        bail("The redis, adam6500, cisco, oracle-listener, s7-300, snmp and "
             "vnc modules are only using the -p or -P option, not login (-l, "
             "-L) or colon file (-C).\nUse the telnet module for cisco using "
             "\"Username:\" authentication.\n");
      if ((hydra_options.login != NULL || hydra_options.loginfile != NULL) && (hydra_options.pass == NULL || hydra_options.passfile == NULL)) {
        hydra_options.pass = hydra_options.login;
        hydra_options.passfile = hydra_options.loginfile;
      }
      hydra_options.login = empty_login;
      hydra_options.loginfile = NULL;
    }
    if (i == 3) {
      if (hydra_options.colonfile != NULL || hydra_options.bfg > 0 || ((hydra_options.login != NULL || hydra_options.loginfile != NULL) && (hydra_options.pass != NULL || hydra_options.passfile != NULL)))
        bail("The rsh, oracle-sid login is neither using the -p, -P or -x "
             "options nor colon file (-C)\n");
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
      bail("I need at least either the -p, -P or -x option to have a password "
           "to try");
    if (i == 1 && hydra_options.login == NULL && hydra_options.loginfile == NULL && hydra_options.colonfile == NULL)
      bail("I need at least either the -l, -L or -C option to know the login");
    if (hydra_options.colonfile != NULL && ((hydra_options.bfg != 0 || hydra_options.login != NULL || hydra_options.loginfile != NULL) || (hydra_options.pass != NULL && hydra_options.passfile != NULL)))
      bail("The -C option is standalone, don't use it with -l/L, -p/P or -x!");
    if ((hydra_options.bfg) && ((hydra_options.pass != NULL) || (hydra_options.passfile != NULL) || (hydra_options.colonfile != NULL)))
      bail("The -x (password bruteforce generation option) doesn't work with "
           "-p/P, -C or -e!\n");
    if (hydra_options.try_password_reverse_login == 0 && hydra_options.try_password_same_as_login == 0 && hydra_options.try_null_password == 0 && (i != 3 && (hydra_options.pass == NULL && hydra_options.passfile == NULL && hydra_options.colonfile == NULL)) && hydra_options.bfg == 0) {
      // test if the service is smtp-enum as it could be used either with a
      // login+pass or only a login
      if (strstr(hydra_options.service, "smtp-enum") != NULL)
        hydra_options.pass = empty_login;
      else
        bail("I need at least the -e, -p, -P or -x option to have some "
             "passwords!");
    }
    if (hydra_options.tasks < 1 || hydra_options.tasks > MAXTASKS) {
      fprintf(stderr, "[ERROR] Option -t needs to be a number between 1 and %d\n", MAXTASKS);
      exit(-1);
    }
    if (hydra_options.max_use > MAXTASKS) {
      fprintf(stderr, "[WARNING] reducing maximum tasks to MAXTASKS (%d)\n", MAXTASKS);
      hydra_options.max_use = MAXTASKS;
    }
    // script kiddie patch
    if (hydra_options.server != NULL && (hydra_strcasestr(hydra_options.server, ".outlook.com") != NULL || hydra_strcasestr(hydra_options.server, ".hotmail.com") != NULL || hydra_strcasestr(hydra_options.server, ".yahoo.") != NULL || hydra_strcasestr(hydra_options.server, ".gmx.") != NULL || hydra_strcasestr(hydra_options.server, ".web.de") != NULL || hydra_strcasestr(hydra_options.server, ".gmail.") != NULL || hydra_strcasestr(hydra_options.server, "googlemail.") != NULL)) {
      fprintf(stderr, "[WARNING] Google Mail and others have bruteforce and "
                      "hydra detection and send false positives. You are not "
                      "doing anything illegal right?!\n");
      fprintf(stderr, "[WARNING] !read the above!\n");
      sleep(5);
    }
    if (hydra_options.colonfile == NULL) {
      if (hydra_options.loginfile != NULL) {
        if ((lfp = fopen(hydra_options.loginfile, "r")) == NULL) {
          fprintf(stderr, "[ERROR] File for logins not found: %s\n", hydra_options.loginfile);
          exit(-1);
        }
        hydra_brains.countlogin = countlines(lfp, 0);
        hydra_brains.sizelogin = size_of_data;
        if (hydra_brains.countlogin == 0) {
          fprintf(stderr, "[ERROR] File for logins is empty: %s\n", hydra_options.loginfile);
          exit(-1);
        }
        if (hydra_brains.countlogin > MAX_LINES) {
          fprintf(stderr, "[ERROR] Maximum number of logins is %d, this file has %" hPRIu64 " entries.\n", MAX_LINES, hydra_brains.countlogin);
          exit(-1);
        }
        if (hydra_brains.sizelogin > MAX_BYTES) {
          fprintf(stderr,
                  "[ERROR] Maximum size of the login file is %d, this file has "
                  "%" hPRIu64 " bytes.\n",
                  MAX_BYTES, (uint64_t)hydra_brains.sizelogin);
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
          fprintf(stderr, "[ERROR] File for passwords not found: %s\n", hydra_options.passfile);
          exit(-1);
        }
        hydra_brains.countpass = countlines(pfp, 0);
        hydra_brains.sizepass = size_of_data;
        if (hydra_brains.countpass == 0) {
          fprintf(stderr, "[ERROR] File for passwords is empty: %s\n", hydra_options.passfile);
          exit(-1);
        }
        if (hydra_brains.countpass > MAX_LINES) {
          fprintf(stderr,
                  "[ERROR] Maximum number of passwords is %d, this file has "
                  "%" hPRIu64 " entries.\n",
                  MAX_LINES, hydra_brains.countpass);
          exit(-1);
        }
        if (hydra_brains.sizepass > MAX_BYTES) {
          fprintf(stderr,
                  "[ERROR] Maximum size of the password file is %d, this file "
                  "has %" hPRIu64 " bytes.\n",
                  MAX_BYTES, (uint64_t)hydra_brains.sizepass);
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
              exit(-1); // error description is handled by bf_init

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
        fprintf(stderr, "[ERROR] File for colon files (login:pass) not found: %s\n", hydra_options.colonfile);
        exit(-1);
      }
      hydra_brains.countlogin = countlines(cfp, 1);
      hydra_brains.sizelogin = size_of_data;
      if (hydra_brains.countlogin == 0) {
        fprintf(stderr, "[ERROR] File for colon files (login:pass) is empty: %s\n", hydra_options.colonfile);
        exit(-1);
      }
      if (hydra_brains.countlogin > MAX_LINES / 2) {
        fprintf(stderr,
                "[ERROR] Maximum number of colon file entries is %d, this file "
                "has %" hPRIu64 " entries.\n",
                MAX_LINES / 2, hydra_brains.countlogin);
        exit(-1);
      }
      if (hydra_brains.sizelogin > MAX_BYTES / 2) {
        fprintf(stderr,
                "[ERROR] Maximum size of the colon file is %d, this file has "
                "%" hPRIu64 " bytes.\n",
                MAX_BYTES / 2, (uint64_t)hydra_brains.sizelogin);
        exit(-1);
      }
      csv_ptr = malloc(hydra_brains.sizelogin + 2 * hydra_brains.countlogin + 8);
      if (csv_ptr == NULL)
        bail("Could not allocate enough memory for colon file data");
      memset(csv_ptr, 0, hydra_brains.sizelogin + 2 * hydra_brains.countlogin + 8);
      fill_mem(csv_ptr, cfp, 1);
      // printf("count: %d, size: %d\n", hydra_brains.countlogin,
      // hydra_brains.sizelogin); hydra_dump_data(csv_ptr,
      // hydra_brains.sizelogin
      // + hydra_brains.countlogin + 8, "colon data");
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
      fprintf(stderr,
              "[WARNING] Restorefile (%s) from a previous session found, to "
              "prevent overwriting, %s\n",
              ignore_restore == 1 ? "ignored ..."
                                  : "you have 10 seconds to abort... (use "
                                    "option -I to skip waiting)",
              RESTOREFILE);
      if (ignore_restore != 1)
        sleep(10);
      fclose(rfp);
    }

    if (hydra_options.infile_ptr != NULL) {
      if ((ifp = fopen(hydra_options.infile_ptr, "r")) == NULL) {
        fprintf(stderr, "[ERROR] File for targets not found: %s\n", hydra_options.infile_ptr);
        exit(-1);
      }
      hydra_brains.targets = countservers = countinfile = countlines(ifp, 0);
      if (countinfile == 0) {
        fprintf(stderr, "[ERROR] File for targets is empty: %s\n", hydra_options.infile_ptr);
        exit(-1);
      }
      // if (countinfile > 60) fprintf(stderr, "[WARNING] the -M option is not
      // working correctly at the moment for target lists > 60!\n");
      hydra_targets = malloc(sizeof(hydra_target *) * (countservers + 2) + 8);
      if (hydra_targets == NULL)
        bail("Could not allocate enough memory for target data");
      sizeinfile = size_of_data;
      if (countinfile > MAX_LINES / 1000) {
        fprintf(stderr,
                "[ERROR] Maximum number of target file entries is %d, this "
                "file has %d entries.\n",
                MAX_LINES / 1000, (int32_t)countinfile);
        exit(-1);
      }
      if (sizeinfile > MAX_BYTES / 1000) {
        fprintf(stderr,
                "[ERROR] Maximum size of the server file is %d, this file has "
                "%d bytes.\n",
                MAX_BYTES / 1000, (int32_t)sizeinfile);
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
          if ((tmpptr2 = strchr(tmpptr, ']')) != NULL) {
            *tmpptr2++ = 0;
            tmpptr = tmpptr2;
          }
        } else
          hydra_targets[i]->target = tmpptr;
        if ((tmpptr2 = strchr(tmpptr, ':')) != NULL) {
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
    } else if (hydra_options.server == NULL) {
      fprintf(stderr, "Error: no target server given, nor -M option used\n");
      exit(-1);
    } else if (strchr(hydra_options.server, '/') != NULL) {
      if (cmdlinetarget == NULL)
        bail("You seem to mix up \"service://target:port/options\" syntax with "
             "\"target service options\" syntax. Read the README on how to use "
             "hydra correctly!");
      if (strstr(cmdlinetarget, "://") != NULL) {
        tmpptr = strchr(hydra_options.server, '/');
        if (tmpptr != NULL)
          *tmpptr = 0;
        countservers = hydra_brains.targets = 1;
        hydra_targets = malloc(sizeof(hydra_target *) * 4);
        hydra_targets[0] = malloc(sizeof(hydra_target));
        memset(hydra_targets[0], 0, sizeof(hydra_target));
        hydra_targets[0]->target = servers_ptr = hydra_options.server;
        hydra_targets[0]->port = hydra_options.port;
        sizeservers = strlen(hydra_options.server) + 1;
      } else {
        /* CIDR notation on command line, e.g. 192.168.0.0/24 */
        uint32_t four_from, four_to, addr_cur, addr_cur2, k, l;
        in_addr_t addr4;
        struct sockaddr_in target;

        hydra_options.cidr = 1;
        do_retry = 0;
        if ((tmpptr = malloc(strlen(hydra_options.server) + 1)) == NULL) {
          fprintf(stderr, "Error: can not allocate memory\n");
          exit(-1);
        }
        strcpy(tmpptr, hydra_options.server);
        tmpptr2 = strchr(tmpptr, '/');
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
        hydra_targets = (hydra_target **)malloc(sizeof(hydra_target *) * (l + 2) + 8);
        if (hydra_targets == NULL)
          bail("Could not allocate enough memory for target data");
        i = 0;
        addr_cur = four_from;
        while (addr_cur <= four_to && i < l) {
          hydra_targets[i] = malloc(sizeof(hydra_target));
          memset(hydra_targets[i], 0, sizeof(hydra_target));
          addr_cur2 = htonl(addr_cur);
          memcpy(&target.sin_addr.s_addr, (char *)&addr_cur2, 4);
          hydra_targets[i]->target = strdup(inet_ntoa((struct in_addr)target.sin_addr));
          hydra_targets[i]->port = hydra_options.port;
          addr_cur++;
          i++;
        }
        if (verbose)
          printf("[VERBOSE] CIDR attack from %s to %s\n", hydra_targets[0]->target, hydra_targets[l - 1]->target);
        printf("[WARNING] The CIDR attack mode is still beta. Please report "
               "issues.\n");
      }
    } else { // standard: single target on command line
      countservers = hydra_brains.targets = 1;
      hydra_targets = malloc(sizeof(hydra_target *) * 4);
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
  } // END OF restore == 0

  // PROXY PROCESSING
  if (getenv("HYDRA_PROXY") && use_proxy == 0) {
    printf("[INFO] Using Connect Proxy: %s\n", getenv("HYDRA_PROXY"));
    use_proxy = 2;
  }
  if (use_proxy == 1)
    proxy_string = getenv("HYDRA_PROXY_HTTP");
  if (use_proxy == 2)
    proxy_string = getenv("HYDRA_PROXY");
  if (use_proxy && getenv("HYDRA_PROXY_AUTH") != NULL)
    fprintf(stderr, "[WARNING] environment variable HYDRA_PROXY_AUTH is "
                    "deprecated, use authentication in the HYDRA_PROXY "
                    "definitions, e.g. type://auth@target:port\n");
  if (use_proxy && proxy_string != NULL) {
    if (strstr(proxy_string, "://") != NULL) {
      process_proxy_line(use_proxy, proxy_string);
    } else {
      if ((proxyfp = fopen(proxy_string, "r")) == NULL) {
        fprintf(stderr,
                "[ERROR] proxy definition %s is neither of the kind "
                "type://auth@target:port nor a file containing proxy entries!\n",
                proxy_string);
        exit(-1);
      }
      while (fgets(buf, sizeof(buf), proxyfp) != NULL)
        process_proxy_line(use_proxy, buf);
      fclose(proxyfp);
    }
    if (proxy_count == 0)
      bail("proxy defined but not valid, exiting");
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
        printf("[VERBOSE] More tasks defined than login/pass pairs exist. "
               "Tasks reduced to %" hPRIu64 "\n",
               hydra_brains.todo);
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
    // fprintf(stderr, "[WARNING] More tasks defined per server than allowed for
    // maximal connections. Tasks per server reduced to %d.\n",
    // hydra_options.tasks);
  } else {
    if (hydra_options.tasks > MAXTASKS) {
      // fprintf(stderr, "[WARNING] reducing tasks to MAXTASKS (%d)\n",
      // MAXTASKS);
      hydra_options.tasks = MAXTASKS;
    }
  }
  //  hydra_options.max_use = hydra_brains.targets * hydra_options.tasks;
  //  if (hydra_options.max_use > MAXTASKS)
  //    hydra_options.max_use = MAXTASKS;
  if (hydra_options.max_use > hydra_options.tasks * hydra_brains.targets)
    hydra_options.max_use = hydra_options.tasks * hydra_brains.targets;
  math2 = (hydra_brains.todo * hydra_brains.targets) / hydra_options.max_use;
  if ((hydra_brains.todo * hydra_brains.targets) % hydra_options.max_use)
    math2++;

  // set options (bits!)
  options = 0;
  if (hydra_options.ssl)
    options = options | OPTION_SSL;

  printf("[DATA] max %d task%s per %d server%s, overall %d task%s, %" hPRIu64 " login tr", hydra_options.tasks, hydra_options.tasks == 1 ? "" : "s", hydra_brains.targets, hydra_brains.targets == 1 ? "" : "s", hydra_options.max_use, hydra_options.max_use == 1 ? "" : "s", hydra_brains.todo);
  printf("%s", hydra_brains.todo == 1 ? "y" : "ies");
  if (hydra_options.colonfile == NULL) {
    printf(" (l:%" hPRIu64 "/p:%" hPRIu64 "), ~%" hPRIu64 " tr", (uint64_t)hydra_brains.countlogin, (uint64_t)hydra_brains.countpass, math2);
  } else {
    printf(", ~%" hPRIu64 " tr", math2);
  }
  printf("%s", math2 == 1 ? "y" : "ies");
  printf(" per task\n");

  if (hydra_brains.targets == 1) {
    if (strchr(hydra_targets[0]->target, ':') == NULL) {
      printf("[DATA] attacking %s%s://%s:", hydra_options.service, hydra_options.ssl == 1 ? "s" : "", hydra_targets[0]->target);
      printf("%d%s%s\n", port, hydra_options.miscptr == NULL || hydra_options.miscptr[0] != '/' ? "/" : "", hydra_options.miscptr != NULL ? hydra_options.miscptr : "");
    } else {
      printf("[DATA] attacking %s%s://[%s]:", hydra_options.service, hydra_options.ssl == 1 ? "s" : "", hydra_targets[0]->target);
      printf("%d%s%s\n", port, hydra_options.miscptr == NULL || hydra_options.miscptr[0] != '/' ? "/" : "", hydra_options.miscptr != NULL ? hydra_options.miscptr : "");
    }
  } else {
    printf("[DATA] attacking %s%s://(%d targets):", hydra_options.service, hydra_options.ssl == 1 ? "s" : "", hydra_brains.targets);
    printf("%d%s%s\n", port, hydra_options.miscptr == NULL || hydra_options.miscptr[0] != '/' ? "/" : "", hydra_options.miscptr != NULL ? hydra_options.miscptr : "");
  }
  // service %s on port %d%s\n", hydra_options.service, port, hydra_options.ssl
  // == 1 ? " with SSL" : "");
  //  if (hydra_options.miscptr != NULL && hydra_options.miscptr[0] != 0)
  //    printf("[DATA] with additional data %s\n", hydra_options.miscptr);

  if (hydra_options.outfile_ptr != NULL) {
    char outfile_open_type[] = "a+"; // Default open in a+ mode
    if (hydra_options.outfile_format == FORMAT_JSONV1 && hydra_options.restore != 1) {
      outfile_open_type[0] = 'w'; // Creat new outfile, if using JSON output and
                                  // not using -R. The open mode should be "w+".
    }
    if ((hydra_brains.ofp = fopen(hydra_options.outfile_ptr, outfile_open_type)) == NULL) {
      perror("[ERROR] Error creating outputfile");
      exit(-1);
    }
    if (hydra_options.outfile_format == FORMAT_JSONV1) {
      if (hydra_options.restore != 1) { // No JSON head while using -R
        fprintf(hydra_brains.ofp,
                "{ \"generator\": {\n"
                "\t\"software\": \"%s\", \"version\": \"%s\", \"built\": \"%s\",\n"
                "\t\"server\": \"%s\", \"service\": \"%s\", \"jsonoutputversion\": "
                "\"1.00\",\n"
                "\t\"commandline\": \"%s",
                PROGRAM, VERSION, hydra_build_time(), hydra_options.server == NULL ? hydra_options.infile_ptr : hydra_options.server, hydra_options.service, prg);
        for (i = 1; i < argc; i++) {
          char *t = hydra_string_replace(argv[i], "\"", "\\\"");
          fprintf(hydra_brains.ofp, " %s", t);
          free(t);
        }
        fprintf(hydra_brains.ofp, "\"\n\t},\n\"results\": [");
      }
    } else { // else default is plain text aka == 0
      fprintf(hydra_brains.ofp, "# %s %s run at %s on %s %s (%s", PROGRAM, VERSION, hydra_build_time(), hydra_options.server == NULL ? hydra_options.infile_ptr : hydra_options.server, hydra_options.service, prg);
      for (i = 1; i < argc; i++)
        fprintf(hydra_brains.ofp, " %s", argv[i]);
      fprintf(hydra_brains.ofp, ")\n");
    }
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
#endif
    if ((device = strchr(hydra_targets[i]->target, '%')) != NULL)
      *device++ = 0;
    if (getaddrinfo(hydra_targets[i]->target, NULL, &hints, &res) != 0) {
      if (use_proxy == 0) {
        if (verbose)
          printf("[failed for %s] ", hydra_targets[i]->target);
        else
          fprintf(stderr, "[ERROR] could not resolve address: %s\n", hydra_targets[i]->target);
        hydra_targets[i]->done = TARGET_UNRESOLVED;
        hydra_brains.finished++;
      }
    } else {
      for (p = res; p != NULL; p = p->ai_next) {
#ifdef AF_INET6
        if (p->ai_family == AF_INET6) {
          if (ipv6 == NULL)
            ipv6 = (struct sockaddr_in6 *)p->ai_addr;
        } else
#endif
            if (p->ai_family == AF_INET) {
          if (ipv4 == NULL)
            ipv4 = (struct sockaddr_in *)p->ai_addr;
        }
      }
#ifdef AF_INET6
      if (ipv6 != NULL && (ipv4 == NULL || prefer_ipv6)) {
        // IPV6 FIXME
        if ((strcmp(hydra_options.service, "socks5") == 0) || (strcmp(hydra_options.service, "sip") == 0)) {
          fprintf(stderr,
                  "[ERROR] Target %s resolves to an IPv6 address, however "
                  "module %s does not support this. Maybe try \"-4\" option. "
                  "Sending in patches helps.\n",
                  hydra_targets[i]->target, hydra_options.service);
          hydra_targets[i]->done = TARGET_UNRESOLVED;
          hydra_brains.finished++;
        } else {
          hydra_targets[i]->ip[0] = 16;
          memcpy(&hydra_targets[i]->ip[1], (char *)&ipv6->sin6_addr, 16);
          if (device != NULL && strlen(device) <= 16)
            strcpy(&hydra_targets[i]->ip[17], device);
          if (memcmp(&hydra_targets[i]->ip[17], fe80, 2) == 0) {
            if (device == NULL) {
              fprintf(stderr,
                      "[ERROR] The target %s address is a link local address, "
                      "link local addresses require the interface being "
                      "defined like this: fe80::1%%eth0\n",
                      hydra_targets[i]->target);
              exit(-1);
            }
          }
        }
      } else
#endif
          if (ipv4 != NULL) {
        hydra_targets[i]->ip[0] = 4;
        memcpy(&hydra_targets[i]->ip[1], (char *)&ipv4->sin_addr, 4);
      } else {
        if (verbose)
          printf("[failed for %s] ", hydra_targets[i]->target);
        else
          fprintf(stderr, "[ERROR] Could not resolve proxy address: %s\n", hydra_targets[i]->target);
        hydra_targets[i]->done = TARGET_UNRESOLVED;
        hydra_brains.finished++;
      }
      freeaddrinfo(res);
    }
    // restore device information if present (overwrite null bytes)
    if (device != NULL) {
      char *tmpptr = device - 1;
      *tmpptr = '%'; // you can ignore the compiler warning
      fprintf(stderr, "[WARNING] not all modules support BINDTODEVICE for IPv6 "
                      "link local addresses, e.g. SSH does not\n");
    }
  }
  if (verbose)
    printf("[VERBOSE] resolving done\n");
  if (hydra_brains.targets == 0)
    bail("No server to scan!");

#ifndef SO_BINDTODEVICE
  if (device != NULL) {
    fprintf(stderr,
            "[ERROR] your operating system does not support SO_BINDTODEVICE or "
            "IP_FORCE_OUT_IFP, dunno how to bind the IPv6 address to the "
            "interface %s!\n",
            device);
  }
#endif

  if (hydra_options.restore == 0) {
    hydra_heads = malloc(sizeof(hydra_head *) * hydra_options.max_use);
    target_no = 0;
    for (i = 0; i < hydra_options.max_use; i++) {
      hydra_heads[i] = malloc(sizeof(hydra_head));
      memset(hydra_heads[i], 0, sizeof(hydra_head));
    }
  }
  // here we call the init function of the relevant service module
  // should we do the init centrally or should each child do that?
  // that depends largely on the number of targets and maximum tasks
  //  if (hydra_brains.targets == 1 || (hydra_brains.targets < 4 &&
  //  hydra_options.tasks / hydra_brains.targets > 4 && hydra_brains.todo > 15))
  for (i = 0; i < hydra_brains.targets; i++)
    hydra_service_init(i);

  starttime = elapsed_status = elapsed_restore = time(NULL);
  fflush(stdout);
  fflush(stderr);
  fflush(hydra_brains.ofp);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  if (hydra_options.ssl) {
    fprintf(stderr, "[WARNING] *****************************************************\n");
    fprintf(stderr, "[WARNING] OPENSSL v1.1 development changes are active - modules "
                    "SMB, SNMP, RDP, ORACLE LISTENER and SSL in general might not work "
                    "properly! Please test and report to vh@thc.org.\n");
    fprintf(stderr, "[WARNING] *****************************************************\n");
  }
#endif

  hydra_debug(0, "attack");
  process_restore = 1;

  // this is the big function which starts the attacking children, feeds
  // login/password pairs, etc.!
  while (exit_condition == 0) {
    memset(&fdreadheads, 0, sizeof(fdreadheads));
    max_fd = 0;
    FD_ZERO(&fdreadheads);
    for (head_no = 0, max_fd = 1; head_no < hydra_options.max_use; head_no++) {
      if (hydra_heads[head_no]->active == HEAD_ACTIVE) {
        FD_SET(hydra_heads[head_no]->sp[0], &fdreadheads);
        if (max_fd < hydra_heads[head_no]->sp[0])
          max_fd = hydra_heads[head_no]->sp[0];
      }
    }
    my_select(max_fd + 1, &fdreadheads, NULL, NULL, 0, 200000);
    tmp_time = time(NULL);

    for (head_no = 0; head_no < hydra_options.max_use; head_no++) {
      if (debug > 1 && hydra_heads[head_no]->active != HEAD_DISABLED)
        printf("[DEBUG] head_no[%d] to target_no %d active %d\n", head_no, hydra_heads[head_no]->target_no, hydra_heads[head_no]->active);

      switch (hydra_heads[head_no]->active) {
      case HEAD_DISABLED:
        break;
      case HEAD_UNUSED:
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
            if (debug)
              printf("[DEBUG] hydra_select_target() reports no more targets "
                     "left\n");
            hydra_kill_head(head_no, 0, 3);
          } else
            hydra_spawn_head(head_no,
                             hydra_heads[head_no]->target_no); // target_no is ignored if head->redo == 1
        }
        break;
      case HEAD_ACTIVE:
        if (FD_ISSET(hydra_heads[head_no]->sp[0], &fdreadheads)) {
          do_switch = 1;
          if (hydra_options.time_next_attempt > 0) {
            if (last_attempt + hydra_options.time_next_attempt >= time(NULL)) {
              if (recv(hydra_heads[head_no]->sp[0], &rc, 1, MSG_PEEK) == 1 && (rc == 'N' || rc == 'n'))
                do_switch = 0;
            } else
              last_attempt = time(NULL);
          }
          if (do_switch) {
            readres = read_safe(hydra_heads[head_no]->sp[0], &rc, 1);
            if (readres > 0) {
              FD_CLR(hydra_heads[head_no]->sp[0], &fdreadheads);
              hydra_heads[head_no]->last_seen = tmp_time;
              if (debug)
                printf("[DEBUG] head_no[%d] read %c\n", head_no, rc);
              switch (rc) {
              // Valid Results:
              //  n - mother says to itself that child requests next
              //  login/password pair N - child requests next login/password
              //  pair Q - child reports that it is quitting C - child reports
              //  connect error (and is quitting) E - child reports protocol
              //  error (and is quitting) f - child reports that the username
              //  does not exist F - child reports that it found a valid
              //  login/password pair
              //        and requests next pair. Sends login/pw pair with next
              //        msg!
              case 'N': // head wants next pair
                hydra_targets[hydra_heads[head_no]->target_no]->ok = 1;
                if (hydra_targets[hydra_heads[head_no]->target_no]->fail_count > 0)
                  hydra_targets[hydra_heads[head_no]->target_no]->fail_count--;
                // no break here
              case 'n': // mother sends this to itself initially
                loop_cnt = 0;
                if (hydra_send_next_pair(hydra_heads[head_no]->target_no, head_no) == -1)
                  hydra_kill_head(head_no, 1, 0);
                break;

              case 'F': // valid password found
                hydra_brains.found++;
                if (colored_output) {
                  if (hydra_heads[head_no]->current_login_ptr == NULL || strlen(hydra_heads[head_no]->current_login_ptr) == 0) {
                    if (hydra_heads[head_no]->current_pass_ptr == NULL || strlen(hydra_heads[head_no]->current_pass_ptr) == 0)
                      printf("[\e[1;32m%d\e[0m][\e[1;32m%s\e[0m] host: "
                             "\e[1;32m%s\e[0m\n",
                             hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target);
                    else
                      printf("[\e[1;32m%d\e[0m][\e[1;32m%s\e[0m] host: "
                             "\e[1;32m%s\e[0m   password: \e[1;32m%s\e[0m\n",
                             hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_pass_ptr);
                  } else if (hydra_heads[head_no]->current_pass_ptr == NULL || strlen(hydra_heads[head_no]->current_pass_ptr) == 0) {
                    printf("[\e[1;32m%d\e[0m][\e[1;32m%s\e[0m] host: "
                           "\e[1;32m%s\e[0m   login: \e[1;32m%s\e[0m\n",
                           hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_login_ptr);
                  } else
                    printf("[\e[1;32m%d\e[0m][\e[1;32m%s\e[0m] host: "
                           "\e[1;32m%s\e[0m   login: \e[1;32m%s\e[0m   password: "
                           "\e[1;32m%s\e[0m\n",
                           hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr);
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
                if (hydra_options.outfile_format == FORMAT_JSONV1 && hydra_options.outfile_ptr != NULL && hydra_brains.ofp != NULL) {
                  fprintf(hydra_brains.ofp,
                          "%s\n\t{\"port\": %d, \"service\": \"%s\", \"host\": "
                          "\"%s\", \"login\": \"%s\", \"password\": \"%s\"}",
                          hydra_brains.found == 1 ? "" : ",", // prefix a comma if not first finding
                          hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target != NULL ? hydra_targets[hydra_heads[head_no]->target_no]->target : "", hydra_heads[head_no]->current_login_ptr != NULL ? hydra_string_replace(hydra_heads[head_no]->current_login_ptr, "\"", "\\\"") : "", hydra_heads[head_no]->current_pass_ptr != NULL ? hydra_string_replace(hydra_heads[head_no]->current_pass_ptr, "\"", "\\\"") : "");
                  fflush(hydra_brains.ofp);
                } else if (hydra_options.outfile_ptr != NULL && hydra_brains.ofp != NULL) { // else output format == 0 aka text
                  if (hydra_heads[head_no]->current_login_ptr == NULL || strlen(hydra_heads[head_no]->current_login_ptr) == 0) {
                    if (hydra_heads[head_no]->current_pass_ptr == NULL || strlen(hydra_heads[head_no]->current_pass_ptr) == 0)
                      fprintf(hydra_brains.ofp, "[%d][%s] host: %s\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target);
                    else
                      fprintf(hydra_brains.ofp, "[%d][%s] host: %s   password: %s\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_pass_ptr);
                  } else if (hydra_heads[head_no]->current_pass_ptr == NULL || strlen(hydra_heads[head_no]->current_pass_ptr) == 0) {
                    fprintf(hydra_brains.ofp, "[%d][%s] host: %s   login: %s\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_login_ptr);
                  } else
                    fprintf(hydra_brains.ofp, "[%d][%s] host: %s   login: %s   password: %s\n", hydra_targets[hydra_heads[head_no]->target_no]->port, hydra_options.service, hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr);
                  fflush(hydra_brains.ofp);
                }
                if (hydra_options.exit_found) { // option set says quit target after on
                                                // valid login/pass pair is found
                  if (hydra_targets[hydra_heads[head_no]->target_no]->done == TARGET_ACTIVE) {
                    hydra_targets[hydra_heads[head_no]->target_no]->done = TARGET_FINISHED; // mark target as done
                    hydra_brains.finished++;
                    printf("[STATUS] attack finished for %s (valid pair found)\n", hydra_targets[hydra_heads[head_no]->target_no]->target);
                  }
                  if (hydra_options.exit_found == 2) {
                    for (j = 0; j < hydra_brains.targets; j++)
                      if (hydra_targets[j]->done == TARGET_ACTIVE) {
                        hydra_targets[j]->done = TARGET_FINISHED;
                        hydra_brains.finished++;
                      }
                  }
                  for (j = 0; j < hydra_options.max_use; j++)
                    if (hydra_heads[j]->active >= 0 && (hydra_heads[j]->target_no == target_no || hydra_options.exit_found == 2)) {
                      if (hydra_brains.targets > hydra_brains.finished && hydra_options.exit_found < 2)
                        hydra_kill_head(j, 1, 0); // kill all heads working on the target
                      else
                        hydra_kill_head(j, 1, 2); // kill all heads working on the target
                    }
                  continue;
                }
                // fall through
              case 'f': // username identified as invalid
                hydra_targets[hydra_heads[head_no]->target_no]->ok = 1;
                if (hydra_targets[hydra_heads[head_no]->target_no]->fail_count > 0)
                  hydra_targets[hydra_heads[head_no]->target_no]->fail_count--;
                memset(buf, 0, sizeof(buf));
                read_safe(hydra_heads[head_no]->sp[0], buf, MAXBUF);
                hydra_skip_user(hydra_heads[head_no]->target_no, buf);
                fck = write(hydra_heads[head_no]->sp[1], "n", 1); // small hack
                break;

              case 'D': // disable target, unknown protocol or feature
                for (j = 0; j < hydra_brains.targets; j++)
                  if (hydra_targets[j]->done == TARGET_ACTIVE) {
                    hydra_targets[j]->done = TARGET_FINISHED;
                    hydra_brains.finished++;
                  }
                for (j = 0; j < hydra_options.max_use; j++)
                  if (hydra_heads[j]->active >= 0 && hydra_heads[j]->target_no == target_no) {
                    if (hydra_brains.targets > hydra_brains.finished)
                      hydra_kill_head(j, 1, 0); // kill all heads working on the target
                    else
                      hydra_kill_head(j, 1, 2); // kill all heads working on the target
                  }
                break;

              // we do not make a difference between 'C' and 'E' results - yet
              case 'E': // head reports protocol error
              case 'C': // head reports connect error
                fck = write(hydra_heads[head_no]->sp[0], "Q", 1);
                if (debug) {
                  printf("[ATTEMPT-ERROR] target %s - login \"%s\" - pass "
                         "\"%s\" - child %d - %" hPRIu64 " of %" hPRIu64 "\n",
                         hydra_targets[hydra_heads[head_no]->target_no]->target, hydra_heads[head_no]->current_login_ptr, hydra_heads[head_no]->current_pass_ptr, head_no, hydra_targets[hydra_heads[head_no]->target_no]->sent, hydra_brains.todo);
                }
                hydra_increase_fail_count(hydra_heads[head_no]->target_no, head_no);
                break;

              case 'Q': // head reports its quitting
                fck = write(hydra_heads[head_no]->sp[0], "Q", 1);
                if (debug)
                  printf("[DEBUG] child %d reported it quit\n", head_no);
                hydra_kill_head(head_no, 1, 0);
                break;

              default:
                fprintf(stderr,
                        "[ERROR] child %d sent nonsense data, killing and "
                        "restarting it!\n",
                        head_no);
                hydra_increase_fail_count(hydra_heads[head_no]->target_no, head_no);
              } // end switch
            }   // readres
            if (readres == -1) {
              if (verbose)
                fprintf(stderr,
                        "[WARNING] child %d seems to have died, restarting "
                        "(this only happens if a module is bad) ... \n",
                        head_no);
              hydra_increase_fail_count(hydra_heads[head_no]->target_no, head_no);
            }
          } // end do_switch
        } else {
          if (hydra_heads[head_no]->last_seen + hydra_options.waittime > tmp_time) {
            // check if recover of timed-out head is necessary
            if (tmp_time > waittime + hydra_heads[head_no]->last_seen) {
              if (kill(hydra_heads[head_no]->pid, 0) < 0) {
                if (verbose)
                  fprintf(stderr,
                          "[WARNING] child %d seems to be dead, restarting it "
                          "...\n",
                          head_no);
                hydra_increase_fail_count(hydra_heads[head_no]->target_no, head_no);
              }
            }
            // if we do not get to hear anything for a longer time assume its
            // dead
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
    // if (debug) printf("DEBUG: bug hunt: %lu %lu\n", hydra_brains.todo_all,
    // hydra_brains.sent);

    usleepn(USLEEP_LOOP);
    (void)waitpid(-1, NULL, WNOHANG);
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
      if (debug == 0) {
        if (status_print < 15 * 59)
          status_print = ((status_print + 1) * 2) - 1;
        if (status_print > 299 && ((hydra_brains.todo_all + total_redo_count) - hydra_brains.sent) / tmp_time < 1500)
          status_print = 299;
        if ((((hydra_brains.todo_all + total_redo_count) - hydra_brains.sent) / tmp_time) < 150)
          status_print = 59;
      }
      k = 0;
      for (j = 0; j < hydra_options.max_use; j++)
        if (hydra_heads[j]->active >= HEAD_UNUSED)
          k++;
      printf("[STATUS] %.2f tries/min, %" hPRIu64 " tries in %02" hPRIu64 ":%02" hPRIu64 "h, %" hPRIu64 " to do in %02" hPRIu64 ":%02" hPRIu64 "h, %d active\n",
             (1.0 * hydra_brains.sent) / (((elapsed_status - starttime) * 1.0) / 60),                                                                                               // tries/min
             hydra_brains.sent,                                                                                                                                                     // tries
             (uint64_t)((elapsed_status - starttime) / 3600),                                                                                                                       // hours
             (uint64_t)(((elapsed_status - starttime) % 3600) / 60),                                                                                                                // minutes
             (hydra_brains.todo_all + total_redo_count) - hydra_brains.sent != 0 ? (hydra_brains.todo_all + total_redo_count) - hydra_brains.sent : 1,                              // left todo
             (uint64_t)(((double)(hydra_brains.todo_all + total_redo_count) - hydra_brains.sent) / ((double)hydra_brains.sent / (elapsed_status - starttime))) / 3600,              // hours
             (((uint64_t)(((double)(hydra_brains.todo_all + total_redo_count) - hydra_brains.sent) / ((double)hydra_brains.sent / (elapsed_status - starttime))) % 3600) / 60) + 1, // min
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
    case TARGET_UNRESOLVED:
      k++;
      break;
    case TARGET_ERROR:
      if (hydra_targets[i]->ok == 0)
        k++;
      else
        error++;
      break;
    case TARGET_FINISHED:
      break;
    case TARGET_ACTIVE:
      if (hydra_targets[i]->ok == 0)
        k++;
      else
        j++;
      break;
    default:
      error++;
      fprintf(stderr, "[ERROR] illegal target result value (%d=>%d)\n", i, hydra_targets[i]->done);
    }

  printf("%d of %d target%s%scompleted, %" hPRIu64 " valid password", hydra_brains.targets - j - k - error, hydra_brains.targets, hydra_brains.targets == 1 ? " " : "s ", hydra_brains.found > 0 ? "successfully " : "", hydra_brains.found);
  printf("%s", hydra_brains.found < 2 ? "" : "s");
  printf(" found\n");

  error += j;
  k = 0;
  for (i = 0; i < hydra_options.max_use; i++)
    if (hydra_heads[i]->active == HEAD_ACTIVE)
      k++;

  if (error == 0 && k == 0) {
    process_restore = 0;
    unlink(RESTOREFILE);
  } else {
    if (hydra_options.cidr == 0 && k == 0) {
      printf("[INFO] Writing restore file because %d server scan%s could not "
             "be completed\n",
             j + error, j + error == 1 ? "" : "s");
      hydra_restore_write(1);
    } else if (k > 0) {
      printf("[WARNING] Writing restore file because %d final worker threads "
             "did not complete until end.\n",
             k);
      hydra_restore_write(1);
    }
  }

  if (debug)
    printf("[DEBUG] killing all remaining children now that might be stuck\n");
  for (i = 0; i < hydra_options.max_use; i++)
    if (hydra_heads[i]->active == HEAD_ACTIVE && hydra_heads[i]->pid > 0)
      hydra_kill_head(i, 1, 3);
  (void)waitpid(-1, NULL, WNOHANG);

#define STRMAX (10 * 1024)
  char json_error[STRMAX + 2], tmp_str[STRMAX + 2];
  memset(json_error, 0, STRMAX + 2);
  memset(tmp_str, 0, STRMAX + 2);
  if (error) {
    snprintf(tmp_str, STRMAX, "[ERROR] %d target%s disabled because of too many errors", error, error == 1 ? " was" : "s were");
    fprintf(stderr, "%s\n", tmp_str);
    strncat(json_error, "\"", STRMAX);
    strncat(json_error, tmp_str, STRMAX);
    strncat(json_error, "\"", STRMAX);
    error = 1;
  }
  if (k) {
    snprintf(tmp_str, STRMAX, "[ERROR] %d target%s did not resolve or could not be connected", k, k == 1 ? "" : "s");
    fprintf(stderr, "%s\n", tmp_str);
    if (*json_error) {
      strncat(json_error, ", ", STRMAX);
    }
    strncat(json_error, "\"", STRMAX);
    strncat(json_error, tmp_str, STRMAX);
    strncat(json_error, "\"", STRMAX);
    error = 1;
  }
  if (error) {
    snprintf(tmp_str, STRMAX, "[ERROR] %d target%s did not complete", j, j < 1 ? "" : "s");
    fprintf(stderr, "%s\n", tmp_str);
    if (*json_error) {
      strncat(json_error, ", ", STRMAX);
    }
    strncat(json_error, "\"", STRMAX);
    strncat(json_error, tmp_str, STRMAX);
    strncat(json_error, "\"", STRMAX);
    error = 1;
    hydra_restore_write(1);
  }
  // yeah we did it
  printf("%s (%s) finished at %s\n", PROGRAM, RESOURCE, hydra_build_time());
  if (hydra_brains.ofp != NULL && hydra_brains.ofp != stdout) {
    if (hydra_options.outfile_format == FORMAT_JSONV1) {
      fprintf(hydra_brains.ofp,
              "\n\t],\n\"success\": %s,\n\"errormessages\": [ %s "
              "],\n\"quantityfound\": %" hPRIu64 "   }\n",
              (error ? "false" : "true"), json_error, hydra_brains.found);
    }
    fclose(hydra_brains.ofp);
  }

  fflush(NULL);
  if (error || j != 0 || exit_condition < 0)
    return -1;
  else
    return 0;
}
