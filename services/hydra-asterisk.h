#ifndef _HYDRA_SERVICE_ASTERISK_H_
#define _HYDRA_SERVICE_ASTERISK_H_

void service_asterisk(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_asterisk_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);

#define SERVICE_ASTERISK { "asterisk", service_asterisk_init, service_asterisk, NULL }

#endif /* _HYDRA_SERVICE_ASTERISK_H_ */
