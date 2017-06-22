#ifndef _HYDRA_SERVICE_SIP_H_
#define _HYDRA_SERVICE_SIP_H_

void service_sip(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_sip_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_sip(const char* service);

#endif /* _HYDRA_SERVICE_SIP_H_ */
