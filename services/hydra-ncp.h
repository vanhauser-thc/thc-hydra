#ifndef _HYDRA_SERVICE_NCP_H_
#define _HYDRA_SERVICE_NCP_H_

void service_ncp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_ncp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_ncp(const char* service);

#define SERVICE_NCP { \
    "ncp", \
    service_ncp_init, \
    service_ncp, \
    usage_ncp \
}

#endif /* _HYDRA_SERVICE_NCP_H_ */
