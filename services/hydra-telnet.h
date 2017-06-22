#ifndef _HYDRA_SERVICE_TELNET_H_
#define _HYDRA_SERVICE_TELNET_H_

void service_telnet(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_telnet_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_telnet(const char* service);

#define SERVICE_TELNET { \
    "telnet", \
    service_telnet_init, \
    service_telnet, \
    usage_telnet \
}

#endif /* _HYDRA_SERVICE_TELNET_H_ */
