#ifndef _HYDRA_MOD_H
#define _HYDRA_MOD_H

#include "hydra.h"

#ifdef __sun
#include <sys/int_types.h>
#elif defined(__FreeBSD__) || defined(__IBMCPP__) || defined(_AIX)
#include <inttypes.h>
#else
#include <stdint.h>
#endif

extern char quiet;

extern void hydra_child_exit(int32_t code);
extern void hydra_register_socket(int32_t s);
extern char *hydra_get_next_pair();
extern char *hydra_get_next_login();
extern char *hydra_get_next_password();
extern void hydra_completed_pair();
extern void hydra_completed_pair_found();
extern void hydra_completed_pair_skip();
extern void hydra_report_found(int32_t port, char *svc, FILE *fp);
extern void hydra_report_pass_found(int32_t port, char *ip, char *svc, FILE *fp);
extern void hydra_report_found_host(int32_t port, char *ip, char *svc, FILE *fp);
extern void hydra_report_found_host_msg(int32_t port, char *ip, char *svc, FILE *fp, char *msg);
extern void hydra_report_debug(FILE *st, char *format, ...);
extern int32_t hydra_connect_to_ssl(int32_t socket, char *hostname);
extern int32_t hydra_connect_ssl(char *host, int32_t port, char *hostname);
extern int32_t hydra_connect_tcp(char *host, int32_t port);
extern int32_t hydra_connect_udp(char *host, int32_t port);
extern int32_t hydra_disconnect(int32_t socket);
extern int32_t hydra_data_ready(int32_t socket);
extern int32_t hydra_recv(int32_t socket, char *buf, uint32_t length);
extern int32_t hydra_recv_nb(int32_t socket, char *buf, uint32_t length);
extern char *hydra_receive_line(int32_t socket);
extern int32_t hydra_send(int32_t socket, char *buf, uint32_t size, int32_t options);
extern int32_t make_to_lower(char *buf);
extern unsigned char hydra_conv64(unsigned char in);
extern void hydra_tobase64(unsigned char *buf, uint32_t buflen, uint32_t bufsize);
extern void hydra_dump_asciihex(unsigned char *string, int32_t length);
extern void hydra_set_srcport(int32_t port);
extern char *hydra_address2string(char *address);
extern char *hydra_address2string_beautiful(char *address);
extern char *hydra_strcasestr(const char *haystack, const char *needle);
extern void hydra_dump_data(unsigned char *buf, int32_t len, char *text);
extern int32_t hydra_memsearch(char *haystack, int32_t hlen, char *needle, int32_t nlen);
extern char *hydra_strrep(char *string, char *oldpiece, char *newpiece);

#ifdef HAVE_PCRE
int32_t hydra_string_match(char *str, const char *regex);
#endif
char *hydra_string_replace(const char *string, const char *substr, const char *replacement);

int32_t debug;
int32_t verbose;
int32_t waittime;
int32_t port;
int32_t found;
int32_t proxy_count;
int32_t use_proxy;
int32_t selected_proxy;
char proxy_string_ip[MAX_PROXY_COUNT][36];
int32_t proxy_string_port[MAX_PROXY_COUNT];
char proxy_string_type[MAX_PROXY_COUNT][10];
char *proxy_authentication[MAX_PROXY_COUNT];
char *cmdlinetarget;

#ifndef __APPLE__
typedef int32_t BOOL;
#else /* __APPLE__ */
/* ensure compatibility with objc libraries */
#if (TARGET_OS_IPHONE && __LP64__) || TARGET_OS_WATCH
typedef bool BOOL;
#else
typedef signed char BOOL;
#endif
#endif /* __APPLE__ */

#define hydra_report fprintf

#endif
