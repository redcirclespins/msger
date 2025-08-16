#include "func.h"

struct AcceptedSocket{
    struct sockaddr_in address;
    int FD;
    int error;
    int success;
};

void receiveDataFromClient(const int clientFD){
    char buffer[1024];
    while(1){
        ssize_t b_recv=recv(clientFD,buffer,sizeof(buffer),0);
        if(b_recv>0){
            buffer[b_recv]=0;
            printf("recved %lld bytes:\n%s\n",b_recv,buffer);
        }
        if(b_recv==0)
            break;
    }
}

struct AcceptedSocket* acceptIncomingConnection(const int serverFD){
    struct sockaddr_in clientAddress;
    int clientAddressSize=sizeof(struct sockaddr_in);
    int clientFD=accept(serverFD,(struct sockaddr*)&clientAddress,&clientAddressSize);
    if(clientFD==-1)
        printf("accept error\n");
    
    struct AcceptedSocket* acceptedSocket=malloc(sizeof(struct AcceptedSocket));
    acceptedSocket->address=clientAddress;
    acceptedSocket->FD=clientFD;
    acceptedSocket->success=clientFD>0;
    if(acceptedSocket->success==0)
        acceptedSocket->error=clientFD;

    receiveDataFromClient(acceptedSocket->FD);
    return acceptedSocket;
}

int main(){
    int serverFD=create_socket();
    struct sockaddr* server_address=create_address("",9999);

    if(bind(serverFD,server_address,sizeof(struct sockaddr))==0)
        printf("successfully bound\n");
    if(listen(serverFD,10)==-1)
        printf("listen error\n");
    struct AcceptedSocket* clientStruct=acceptIncomingConnection(serverFD);

    close(clientStruct->FD);
    shutdown(serverFD,SHUT_RDWR);
    return 0;
}
