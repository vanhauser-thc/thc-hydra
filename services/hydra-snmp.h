#ifndef _HYDRA_SERVICE_SNMP_H_
#define _HYDRA_SERVICE_SNMP_H_

void service_snmp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_snmp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_snmp(const char* service);

#endif /* _HYDRA_SERVICE_SNMP_H_ */
