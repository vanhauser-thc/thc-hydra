#ifndef _HYDRA_SERVICE_IRC_H_
#define _HYDRA_SERVICE_IRC_H_

void service_irc(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_irc_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_irc(const char* service);

#define SERVICE_IRC { \
    "irc", \
    service_irc_init, \
    service_irc, \
    usage_irc \
}

#endif /* _HYDRA_SERVICE_IRC_H_ */
