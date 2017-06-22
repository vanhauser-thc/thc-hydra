#ifndef _HYDRA_SERVICE_LDAP_H_
#define _HYDRA_SERVICE_LDAP_H_

void service_ldap2(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void service_ldap3(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void service_ldap3_cram_md5(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void service_ldap3_digest_md5(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_ldap_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_ldap(const char* service);

#endif /* _HYDRA_SERVICE_LDAP_H_ */
