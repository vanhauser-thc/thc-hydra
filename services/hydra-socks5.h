#ifndef _HYDRA_SERVICE_SOCKS5_H_
#define _HYDRA_SERVICE_SOCKS5_H_

void service_socks5(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_socks5_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_socks5(const char* service);

#endif /* _HYDRA_SERVICE_SOCKS5_H_ */
