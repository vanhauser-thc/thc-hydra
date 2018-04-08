//
//  output-redis.c
//  output-redis
//
//  Created by zhukun on 03/04/18.
//
//

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "lib/hiredis/hiredis.h"

#define REDIS_IP     "127.0.0.1"
#define REDIS_PORT     6379

redisContext *conn;

void set(const unsigned char *key, const unsigned char *value);
void get(char *value, const unsigned char *key);
void lpush(const unsigned char *key, const unsigned char *value);
void key(char *map_key, const unsigned char *str);
void redis_free();

char *replace(char *src, char *sub, char *dst);