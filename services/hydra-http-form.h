#ifndef _HYDRA_SERVICE_HTTP_FORM_H_
#define _HYDRA_SERVICE_HTTP_FORM_H_

void service_http_post_form(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void service_http_get_form(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_http_form_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_http_form(const char* service);

#endif /* _HYDRA_SERVICE_HTTP_FORM_H_ */
