//
//  hydra-rtsp.c
//  hydra-rtsp
//
//  Created by Javier zhukun on 03/04/18.
//
//

#include <stdio.h>
#include "lib/hiredis/hiredis.h"

redisContext *conn;

void set(const unsigned char *key, const unsigned char *value);
void redis_free();