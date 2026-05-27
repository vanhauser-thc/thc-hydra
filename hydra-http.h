#ifndef _HYDRA_HTTP_H
#define _HYDRA_HTTP_H

#include "hydra-mod.h"

/*	HTTP Header Types	*/
#define HEADER_TYPE_USERHEADER 'h'
#define HEADER_TYPE_USERHEADER_REPL 'H'
#define HEADER_TYPE_DEFAULT 'D'
#define HEADER_TYPE_DEFAULT_REPL 'd'

#define REDIRECT_CONDITION_MAX_LEN 256
#define REDIRECT_CONDITION_FAILURE 0
#define REDIRECT_CONDITION_SUCCESS 1
#define REDIRECT_CONDITION_LOCATION 2

typedef struct header_node t_header_node, *ptr_header_node;

extern char *webtarget;
extern char *slash;
extern char *optional1;
extern char redirect_condition[REDIRECT_CONDITION_MAX_LEN];
extern int redirect_condition_type;

extern int32_t parse_options(char *miscptr, ptr_header_node *ptr_head);
extern int32_t add_header(ptr_header_node *ptr_head, char *header, char *value, char type);
extern char *stringify_headers(ptr_header_node *ptr_head);
#endif
