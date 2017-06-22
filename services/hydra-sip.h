#ifndef _HYDRA_SERVICE_SIP_H_
#define _HYDRA_SERVICE_SIP_H_

void service_sip(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_sip_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);

#define SERVICE_SIP { \
    "sip", \
    service_sip_init, \
    service_sip, \
    NULL \
}

#endif /* _HYDRA_SERVICE_SIP_H_ */
