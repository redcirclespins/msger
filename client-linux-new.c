//tls:enabled
#include <stdio.h>
#include <ctype.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER 1025
#define NICKNAME 33
#define FILE_BUFFER 4097
//one extra for \0

void error(const char* msg){
    perror(msg);
    exit(1);
}

void std_error(const char* msg){
    fprintf(stderr,"%s",msg);
    exit(1);
}

//better to do server-side checking for nickname length for security
//becuse client-side can be manipulted in theory
//though to optimize the client heres the code
int is_valid_nickname(char* nickname){
    size_t len=strlen(nickname);
    if(len>0&&nickname[len-1]=='\n'){
        nickname[len-1]='\0';
        len--;
    }
    if(len==0||len>=NICKNAME)
        return 0;
    for(size_t i=0;i<len;i++){
        unsigned char ch=nickname[i];
        if(!isalnum(ch)&&ch!='_'&&ch!='-')
            return 0;
    }
    return 1; //success
}

int main(int argc,char** argv){
    if(argc!=3)
        std_error("usage: ./client hostname port\n");
    for(int i=0;argv[2][i];i++){
        if(!isdigit(argv[2][i]))
            std_error("provide valid port\n");
    }
    struct sockaddr_in serv_addr;
    struct hostent* server;
    char nickname[NICKNAME]={0};
    char buffer[BUFFER]={0};
    int port=atoi(argv[2]);
    int printed_prompt=0;
    int sockfd=0;
    fd_set readfds;

    server=gethostbyname(argv[1]);
    if(server==NULL)
        std_error("provide valid host\n");

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX* ctx=SSL_CTX_new(TLS_client_method());
    if(!ctx)
        error("ssl_ctx error");

    sockfd=socket(AF_INET,SOCK_STREAM,0);
    if(sockfd==-1)
        error("socket error");
    //can also use bzero and bcopy
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_port=htons(port);
    memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
    if(connect(sockfd,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1)
        error("connect error");

    SSL* ssl=SSL_new(ctx);
    SSL_set_fd(ssl,sockfd);
    if(SSL_connect(ssl)<=0)
        error("ssl connect error");

    printf("enter nickname(max 32 chars): ");
    if(!fgets(nickname,NICKNAME,stdin)||!is_valid_nickname(nickname))
        std_error("invalid nickname. disconnecting...\n");
    SSL_write(ssl,nickname,strlen(nickname));

    //better send verif messages that dont impact the workflow from client-side
    //rather than always request info from server
    printf("----------------------------------\n");
    printf("connected to chat\n");
    printf("type '.quit' to exit\n");
    printf("type '.online' to see users online\n");
    printf("----------------------------------\n");

    fcntl(sockfd,F_SETFL,O_NONBLOCK);
    while(1){
        FD_ZERO(&readfds);
        FD_SET(0,&readfds); //stdin
        FD_SET(sockfd,&readfds); //socket
        if(!printed_prompt){
            printf("--> ");
            fflush(stdout);
            printed_prompt=1;
        }
        if(select(sockfd+1,&readfds,NULL,NULL,NULL)==-1)
            error("select error");
        //msgs from server
        if(FD_ISSET(sockfd,&readfds)){
            bzero(buffer,BUFFER);
            int n=SSL_read(ssl,buffer,BUFFER-1);
            if(n<=0){
                int ssl_err=SSL_get_error(ssl,n);
                if(ssl_err==SSL_ERROR_WANT_READ||ssl_err==SSL_ERROR_WANT_WRITE)
                    continue;
                printf("server disconnected.\n");
                break;
            }
            buffer[n]='\0';
            //remove current line and print server msg
            printf("\r\033[K%s",buffer);
            if(buffer[n-1]!='\n')
                printf("\n");
            printf("--> ");
            fflush(stdout);
            printed_prompt=1;
        }
        //user input
        if(FD_ISSET(0,&readfds)){
            bzero(buffer,BUFFER);
            fgets(buffer,BUFFER,stdin);
            buffer[strcspn(buffer,"\r\n")]='\0';
            int written=SSL_write(ssl,buffer,strlen(buffer));
            if(strcmp(buffer,".quit")==0)
                break;
            else if(strncmp(buffer,".file",5)==0){
                char* path_start=buffer+5;
                while(*path_start==' ')
                    path_start++;
                FILE *fp=fopen(path_start,"rb");
                if(!fp){
                    printf("cannot open file: %s\n",path_start);
                    continue;
                }
                fseek(fp,0,SEEK_END);
                long filesize=ftell(fp);
                fseek(fp,0,SEEK_SET);
                char* filename=strrchr(path_start,'/');
                filename=filename?filename+1:path_start;
                char control[256];
                snprintf(control,sizeof(control),".file %s %ld",filename,filesize);
                SSL_write(ssl,control,strlen(control));
                char file_buffer[FILE_BUFFER];
                int bytes;
                while((bytes=fread(file_buffer,1,sizeof(file_buffer),fp))>0)
                    SSL_write(ssl,file_buffer,bytes);
                fclose(fp);
                printf("file sent: %s (%ld bytes)\n",filename,filesize);
            }
            if(written<=0){
                int ssl_err=SSL_get_error(ssl,written);
                if(ssl_err!=SSL_ERROR_WANT_READ||ssl_err!=SSL_ERROR_WANT_WRITE)
                    break;
            }
            printed_prompt=0;
        }
    }
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
