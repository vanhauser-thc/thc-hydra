#ifndef _HYDRA_SERVICE_CVS_H_
#define _HYDRA_SERVICE_CVS_H_

void service_cvs(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_cvs_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_cvs(const char* service);

#define SERVICE_CVS { "cvs", service_cvs_init, service_cvs, usage_cvs }

#endif /* _HYDRA_SERVICE_CVS_H_ */
