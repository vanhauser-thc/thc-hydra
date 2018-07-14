#ifndef _HYDRA_HTTP_H
#define _HYDRA_HTTP_H

typedef struct header_node t_header_node, *ptr_header_node;

extern char *webtarget;
extern char *slash;
extern char *optional1;

extern ptr_header_node parse_options(char *miscptr);
#endif
