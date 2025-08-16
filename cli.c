#include "func.h"

int main(){
    char* ip="localhost";
    uint16_t port=9999;
    int fd=create_socket();
    struct sockaddr* address=create_address(ip,port);

    int result=connect(fd,address,sizeof(*address));
    if(result==0)
        printf("successfully connected!\n");

    char* msg=NULL;
    size_t msg_size=0;
    while(1){
        ssize_t b_send=getline(&msg,&msg_size,stdin);
        if(b_send>0){
            if(strcmp(msg,"exit\n")==0)
                break;
            ssize_t b_sent=send(fd,msg,strlen(msg),0);
            printf("sent %lld bytes\n",b_send);
        }
    }

    close(fd);
    //char buffer[1024];
    //ssize_t b_recv=recv(fd,buffer,sizeof(buffer),0);
    //printf("recved %lld bytes:\n%s\n",b_recv,buffer);
    return 0;
}
