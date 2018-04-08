//
//  hydra-rtsp.c
//  hydra-rtsp
//
//  Created by Javier zhukun on 03/04/18.
//
//

#include "output-redis.h"

void set(const unsigned char *key, const unsigned char *value)
{
	if (conn == NULL)
	{
		conn = redisConnect(REDIS_IP, REDIS_PORT);
	}
	if(conn != NULL && conn->err) 
	{
		printf("connection error: %s\n",conn->errstr); 
	}
	redisReply *reply = (redisReply*)redisCommand(conn,"set %s %s", key, value); 
	freeReplyObject(reply); 
}

void get(char *value, const unsigned char *key)
{
	if (conn == NULL)
	{
		conn = redisConnect(REDIS_IP, REDIS_PORT);
	}
	if(conn != NULL && conn->err) 
	{
		printf("connection error: %s\n",conn->errstr);
	}
	redisReply *reply = redisCommand(conn,"get %s", key);
	sprintf(value, "%s", reply->str);
	freeReplyObject(reply);
}

void lpush(const unsigned char *key, const unsigned char *value)
{
	if (conn == NULL)
	{
		conn = redisConnect("127.0.0.1", 6379);
	}
	if(conn != NULL && conn->err) 
	{
		printf("connection error: %s\n",conn->errstr); 
	}
	redisReply *reply = (redisReply*)redisCommand(conn,"lpush %s %s", key, value); 
	freeReplyObject(reply);
}

void key(char *key, const unsigned char *str){
	//随机种子
	srand(time(0));
	sprintf(key, "%s-%d", str, rand());
}

void redis_free()
{
	redisFree(conn);
}
char *replace(char *src, char *sub, char *dst)
{
	int pos = 0;
	int offset = 0;
	int srcLen, subLen, dstLen;
	char *pRet = NULL;
 
	srcLen = strlen(src);
	subLen = strlen(sub);
	dstLen = strlen(dst);
	pRet = (char *)malloc(srcLen + dstLen - subLen + 1);//(外部是否该空间)
	if (NULL != pRet)
	{
		pos = strstr(src, sub) - src;
		memcpy(pRet, src, pos);
		offset += pos;
		memcpy(pRet + offset, dst, dstLen);
		offset += dstLen;
		memcpy(pRet + offset, src + pos + subLen, srcLen - pos - subLen);
		offset += srcLen - pos - subLen;
		*(pRet + offset) = '\0';
	}
	return pRet;
}
/*int main() 
{ 
	set("a", "1");
	return 0;
}*/
