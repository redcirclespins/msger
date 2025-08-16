#include "func.h"

struct sockaddr* create_address(const char* ip,const int port){
    struct sockaddr_in* address=malloc(sizeof(struct sockaddr_in));
    address->sin_family=AF_INET;
    address->sin_port=htons(port);
    if(strlen(ip)==0)
        address->sin_addr.s_addr=INADDR_ANY;
    else
        inet_pton(AF_INET,ip,&address->sin_addr.s_addr);
    return (struct sockaddr*)address;
}

int create_socket(){return socket(AF_INET,SOCK_STREAM,0);}
