#ifndef _HYDRA_SERVICE_VMAUTHD_H_
#define _HYDRA_SERVICE_VMAUTHD_H_

void service_vmauthd(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);
int service_vmauthd_init(char *ip, int sp, unsigned char options, char *miscptr, FILE * fp, int port, char *hostname);

#define SERVICE_VMAUTHD { \
    "vmauthd", \
    service_vmauthd_init, \
    service_vmauthd, \
    NULL \
}

#endif /* _HYDRA_SERVICE_VMAUTHD_H_ */
