#ifndef _HYDRA_SERVICE_ADAM6500_H_
#define _HYDRA_SERVICE_ADAM6500_H_

void service_adam6500(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_adam6500_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);

#define SERVICE_ADAM6500 { "adam6500", service_adam6500_init, service_adam6500, NULL }

#endif /* _HYDRA_SERVICE_ADAM6500_H_ */
