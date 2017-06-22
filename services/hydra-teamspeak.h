#ifndef _HYDRA_SERVICE_TEAMSPEAK_H_
#define _HYDRA_SERVICE_TEAMSPEAK_H_

void service_teamspeak(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_teamspeak_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);

#define SERVICE_TEAMSPEAK { \
    "teamspeak", \
    service_teamspeak_init, \
    service_teamspeak, \
    NULL \
}

#endif /* _HYDRA_SERVICE_TEAMSPEAK_H_ */
