#ifndef _HYDRA_SERVICE_HTTP_H_
#define _HYDRA_SERVICE_HTTP_H_

void service_http_get(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void service_http_head(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void service_http_post(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_http_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
void usage_http(const char* service);

#define SERVICE_HTTP_GET { \
    "http-get", \
    service_http_init, \
    service_http_get, \
    usage_http \
}

#define SERVICE_HTTP_HEAD { \
    "http-head", \
    service_http_init, \
    service_http_head, \
    NULL \
}

#define SERVICE_HTTP_POST { \
    "http-post", \
    NULL, \
    service_http_post, \
    usage_http \
}

#endif /* _HYDRA_SERVICE_HTTP_H_ */
