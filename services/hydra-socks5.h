#ifndef _HYDRA_SERVICE_SOCKS5_H_
#define _HYDRA_SERVICE_SOCKS5_H_

void service_socks5(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_socks5_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);

#define SERVICE_SOCKS5 { \
    "socks5", \
    service_socks5_init, \
    service_socks5, \
    NULL \
}

#endif /* _HYDRA_SERVICE_SOCKS5_H_ */
