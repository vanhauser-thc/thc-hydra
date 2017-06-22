#ifndef _HYDRA_SERVICE_FIREBIRD_H_
#define _HYDRA_SERVICE_FIREBIRD_H_

void service_firebird(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_firebird_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_firebird(const char* service);

#define SERVICE_FIREBIRD { "firebird", service_firebird_init, service_firebird, usage_firebird }

#endif /* _HYDRA_SERVICE_FIREBIRD_H_ */
