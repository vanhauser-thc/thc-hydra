#ifndef _HYDRA_MOD_H
#define _HYDRA_MOD_H

#include "hydra.h"

extern void hydra_child_exit(int code);
extern void hydra_register_socket(int s);
extern char *hydra_get_next_pair();
extern char *hydra_get_next_login();
extern char *hydra_get_next_password();
extern void hydra_completed_pair();
extern void hydra_completed_pair_found();
extern void hydra_completed_pair_skip();
extern void hydra_report_found(int port, char *svc, FILE * fp);
extern void hydra_report_pass_found(int port, char *ip, char *svc, FILE * fp);
extern void hydra_report_found_host(int port, char *ip, char *svc, FILE * fp);
extern void hydra_report_found_host_msg(int port, char *ip, char *svc, FILE * fp, char *msg);
extern void hydra_report_debug(FILE *st, char *format, ...);
extern int hydra_connect_to_ssl(int socket);
extern int hydra_connect_ssl(char *host, int port);
extern int hydra_connect_tcp(char *host, int port);
extern int hydra_connect_udp(char *host, int port);
extern int hydra_disconnect(int socket);
extern int hydra_data_ready(int socket);
extern int hydra_recv(int socket, char *buf, int length);
extern int hydra_recv_nb(int socket, char *buf, int length);
extern char *hydra_receive_line(int socket);
extern int hydra_send(int socket, char *buf, int size, int options);
extern int make_to_lower(char *buf);
extern unsigned char hydra_conv64(unsigned char in);
extern void hydra_tobase64(unsigned char *buf, int buflen, int bufsize);
extern void hydra_dump_asciihex(unsigned char *string, int length);
extern void hydra_set_srcport(int port);
extern char *hydra_address2string(char *address);
extern char *hydra_strcasestr(const char *haystack, const char *needle);
extern void hydra_dump_data(unsigned char *buf, int len, char *text);
extern int hydra_memsearch(char *haystack, int hlen, char *needle, int nlen);
extern char *hydra_strrep(char *string, char *oldpiece, char *newpiece);

#ifdef HAVE_PCRE
int hydra_string_match(char *str, const char *regex);
#endif
char *hydra_string_replace(const char *string, const char *substr, const char *replacement);

int debug;
int verbose;
int waittime;
int port;
int use_proxy;
int found;
char proxy_string_ip[36];
int proxy_string_port;
char proxy_string_type[10];
char *proxy_authentication;
char *cmdlinetarget;

typedef int BOOL;

#define hydra_report fprintf

#endif
