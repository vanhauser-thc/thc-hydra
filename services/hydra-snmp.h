#ifndef _HYDRA_SERVICE_SNMP_H_
#define _HYDRA_SERVICE_SNMP_H_

void service_snmp(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_snmp_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_snmp(const char* service);

#define SERVICE_SNMP { \
    "snmp", \
    service_snmp_init, \
    service_snmp, \
    usage_snmp \
}

#endif /* _HYDRA_SERVICE_SNMP_H_ */
