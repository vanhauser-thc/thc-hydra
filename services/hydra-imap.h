#ifndef _HYDRA_SERVICE_IMAP_H_
#define _HYDRA_SERVICE_IMAP_H_

void service_imap(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_imap_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_imap(const char* service);

#define SERVICE_IMAP { \
    "imap", \
    service_imap_init, \
    service_imap, \
    usage_imap \
}

#endif /* _HYDRA_SERVICE_IMAP_H_ */
