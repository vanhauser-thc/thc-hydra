#ifndef _HYDRA_SERVICE_RDP_H_
#define _HYDRA_SERVICE_RDP_H_

void service_rdp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_rdp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_rdp(const char* service);

#endif /* _HYDRA_SERVICE_RDP_H_ */
