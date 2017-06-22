#ifndef _HYDRA_SERVICE_VNC_H_
#define _HYDRA_SERVICE_VNC_H_

void service_vnc(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_vnc_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_vnc(const char* service);

#endif /* _HYDRA_SERVICE_VNC_H_ */
