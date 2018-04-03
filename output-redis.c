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
		conn = redisConnect("127.0.0.1", 6379);
	}
     if(conn != NULL && conn->err) 
     {
         
         printf("connection error: %s\n",conn->errstr); 
     }
     redisReply *reply = (redisReply*)redisCommand(conn,"set %s %s", key, value); 
     freeReplyObject(reply); 
     
     /*reply = redisCommand(conn,"get %s", key); 
     printf("%s\n",reply->str); 
     freeReplyObject(reply); */
             
     
}

void redis_free()
{
	redisFree(conn);
}
/*int main() 
{ 
    set("a", "1");
	return 0;
}*/
