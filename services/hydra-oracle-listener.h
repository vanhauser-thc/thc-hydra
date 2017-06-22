#ifndef _HYDRA_SERVICE_ORACLE_LISTENER_H_
#define _HYDRA_SERVICE_ORACLE_LISTENER_H_

void service_oracle_listener(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_oracle_listener_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_oracle_listener(const char* service);

#define SERVICE_ORACLE_LISTENER { \
    "oracle-listener", \
    service_oracle_listener_init, \
    service_oracle_listener, \
    usage_oracle_listener \
}

#endif /* _HYDRA_SERVICE_ORACLE_LISTENER_H_ */
