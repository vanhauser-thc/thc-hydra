#ifndef _HYDRA_SERVICE_XMPP_H_
#define _HYDRA_SERVICE_XMPP_H_

void service_xmpp(char *target, char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_xmpp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_xmpp(const char* service);

#define SERVICE_XMPP { \
    "xmpp", \
    service_xmpp_init, \
    NULL, \
    usage_xmpp \
}

#endif /* _HYDRA_SERVICE_XMPP_H_ */
