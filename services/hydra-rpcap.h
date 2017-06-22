#ifndef _HYDRA_SERVICE_RPCAP_H_
#define _HYDRA_SERVICE_RPCAP_H_

void service_rpcap(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_rpcap_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);

#define SERVICE_RPCAP { \
    "rpcap", \
    service_rpcap_init, \
    service_rpcap, \
    NULL \
}

#endif /* _HYDRA_SERVICE_RPCAP_H_ */
