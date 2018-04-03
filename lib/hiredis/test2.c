#include <stdio.h> 
#include "hiredis.h"
int main() 
{ 
     redisContext *conn  = redisConnect("127.0.0.1",6379); 
     if(conn != NULL && conn->err) 
     {   
         printf("connection error: %s\n",conn->errstr); 
         return 0; 
     }   
     redisReply *reply = (redisReply*)redisCommand(conn,"set foo 1234"); 
     freeReplyObject(reply); 
             
     reply = redisCommand(conn,"get foo"); 
     printf("%s\n",reply->str); 
     freeReplyObject(reply); 
             
     redisFree(conn); 
     return 0; 
}
