//tls:enabled
#include <time.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FILE_BUFFER 4096
#define MSG_BUFFER 1027 //+": \0"
#define FILE_PATH 256
#define FILE_NAME 128
#define MAX_CLIENTS 2
#define NICKNAME 33 //+\0

unsigned debug=0;
unsigned debug_move=0;
int fd_clients[MAX_CLIENTS]={0};
SSL* ssl_clients[MAX_CLIENTS]={0};
char buffer[MSG_BUFFER+NICKNAME-1]={0};
char nicknames[MAX_CLIENTS][NICKNAME]={0};

/*
void info_callback(const SSL* ssl,int type,int val){
    if(type==SSL_CB_HANDSHAKE_START)
        printf("ssl handshake starting\n");
    else if(type==SSL_CB_HANDSHAKE_DONE)
        printf("ssl handshake completed\n");
}
*/

void error(const char* msg){
    perror(msg);
    exit(1);
}

void std_error(const char* msg){
    fprintf(stderr,"%s",msg);
    exit(1);
}

int is_valid_nickname(char* nickname){
    size_t len=strlen(nickname);
    if(len>0&&nickname[len-1]=='\n'){
        nickname[len-1]='\0';
        len--;
    }
    if(!len||len>=NICKNAME)
        return 0;
    for(size_t i=0;i<len;i++){
        unsigned char ch=nickname[i];
        if(!isalnum(ch)&&ch!='_'&&ch!='-')
            return 0;
    }
    return 1; //success
}

//requires fd_clients[i] of a user responsible for the info sending to all others
void send_to_others(const int id,const char* msg){
    for(int i=0;i<MAX_CLIENTS;i++){
        if(fd_clients[i]&&i!=id)
            SSL_write(ssl_clients[i],msg,strlen(msg));
    }
}

void send_back(const int id,const char* msg){
    if(fd_clients[id])
        SSL_write(ssl_clients[id],msg,strlen(msg));
}

int special_req(char* buffer,const int i,const int debug){
    char temp[MSG_BUFFER+NICKNAME-1]={0};
    if(strcmp(buffer,".quit")==0){
        close(fd_clients[i]);
        SSL_free(ssl_clients[i]);
        fd_clients[i]=0;
        ssl_clients[i]=NULL;
        sprintf(temp,"client '%s' quit!\n",nicknames[i]);
        send_to_others(i,temp);
        if(debug==1)
            printf("client '%s' quit (socket %d)\n",nicknames[i],fd_clients[i]);
    }else if(strcmp(buffer,".online")==0){
        sprintf(temp,"online: ");
        int first=1;
        for(int j=0;j<MAX_CLIENTS;j++){
            if(fd_clients[j]&&j!=i){
                if(!first)
                    strncat(temp,",",MSG_BUFFER+NICKNAME-1-strlen(temp)-1);
                strncat(temp,nicknames[j],MSG_BUFFER+NICKNAME-1-strlen(temp)-1);
                first=0;
            }
        }
        if(first)
            strncat(temp,"no one else",MSG_BUFFER+NICKNAME-1-strlen(temp)-1);
        strncat(temp,"\n",MSG_BUFFER+NICKNAME-1-strlen(temp)-1);
        send_back(i,temp);
        if(debug==1)
            printf("client '%s' requested .online (socket %d)\n",nicknames[i],fd_clients[i]);
    }else if(strncmp(buffer,".file",5)==0){
        char file_buffer[FILE_BUFFER];
        char filepath[FILE_PATH];
        char filename[FILE_NAME];
        long filesize=0;
        long received=0;
        int read=sscanf(buffer+6,"%127s %ld",filename,&filesize);
        if(read!=2||filesize<=0){
            send_back(i,"invalid .file command\nusage: .file <filename>");
            return 1;
        }
        snprintf(filepath,sizeof(filepath),"%s",filename);
        FILE *fp=fopen(filepath,"wb");
        if(!fp){
            send_back(i,"failed to open file on server\n");
            return 1;
        }
        while(received<filesize){
            int to_read=(filesize-received)>FILE_BUFFER?FILE_BUFFER:(filesize-received);
            int n=SSL_read(ssl_clients[i],file_buffer,to_read);
            if(n<=0)
                break;
            fwrite(file_buffer,1,n,fp);
            received+=n;
        }
        fclose(fp);
        snprintf(temp,sizeof(temp),"file '%s' received (%ld bytes)\n",filename,filesize);
        send_back(i,temp);
        if(debug==1)
            printf("'%s' (socket %d) sent a file: '%s' (%ld bytes)\n",nicknames[i],fd_clients[i],filename,filesize);
    }else{
        char temp[NICKNAME+3]; //": "+\0
        snprintf(temp,sizeof(temp),"%s: ",nicknames[i]);
        size_t prefix_len=strlen(temp);
        memmove(buffer+prefix_len,buffer,strlen(buffer)+1); //+1 to move \0
        memcpy(buffer,temp,prefix_len);
        send_to_others(i,buffer);
        if(debug==1)
            printf("message from '%s' (socket %d): %s\n",nicknames[i],fd_clients[i],buffer);
    }
    return 0;
}

int main(int argc,char** argv){
    for(int i=0;i<argc;i++){
        if(!strcmp(argv[i],"--debug")){
            debug=1;
            if(i<argc-1)
                debug_move=1;
        }
    }
    if(argc!=2){
        if(argc==3&&!debug)
            std_error("usage: ./server port\n");
    }
    for(int i=0;argv[1+debug_move][i];i++){
        if(!isdigit(argv[1+debug_move][i]))
            std_error("provide valid port\n");
    }

    struct sockaddr_in serv_addr,cli_addr;
    int sockfd,newsockfd;
    int port=atoi(argv[1+debug_move]);
    int opt=1;
    socklen_t clilen=sizeof(cli_addr);
    fd_set readfds;

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_CTX* ctx=SSL_CTX_new(TLS_server_method());
    if(!ctx){
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    SSL_CTX_set_cipher_list(ctx,"HIGH:!aNULL:!MD5");
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx,SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1);
    //if(SSL_CTX_use_certificate_file(ctx,"/etc/ssl/private/cert.pem",SSL_FILETYPE_PEM)<=0||
    //   SSL_CTX_use_PrivateKey_file(ctx,"/etc/ssl/private/key.pem",SSL_FILETYPE_PEM)<=0){
    if(SSL_CTX_use_certificate_file(ctx,"cert.pem",SSL_FILETYPE_PEM)<=0||
       SSL_CTX_use_PrivateKey_file(ctx,"key.pem",SSL_FILETYPE_PEM)<=0){
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if(!SSL_CTX_check_private_key(ctx)){
        fprintf(stderr,"private key does not match certificate\n");
        exit(1);
    }

    sockfd=socket(AF_INET,SOCK_STREAM,0);
    if(sockfd==-1)
        error("socket error");
    setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    //can also use bzero and bcopy
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_addr.s_addr=INADDR_ANY;
    serv_addr.sin_port=htons(port);
    if(bind(sockfd,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1)
        error("bind error");
    if(listen(sockfd,MAX_CLIENTS)==-1)
        error("listen error");
    printf("server started on port %d\n",port);

    while(1){
        FD_ZERO(&readfds);
        FD_SET(sockfd,&readfds);
        int max_sd=sockfd;
        for(int i=0;i<MAX_CLIENTS;i++){
            if(fd_clients[i]>0)
                FD_SET(fd_clients[i],&readfds);
            if(fd_clients[i]>max_sd)
                max_sd=fd_clients[i];
        }
        if(select(max_sd+1,&readfds,NULL,NULL,NULL)==-1)
            error("select error");
        if(FD_ISSET(sockfd,&readfds)){
            newsockfd=accept(sockfd,(struct sockaddr*)&cli_addr,&clilen);
            if(newsockfd==-1)
                error("accept error");
            //SSL_CTX_set_info_callback(ctx,info_callback);
            SSL* ssl=SSL_new(ctx);
            SSL_set_fd(ssl,newsockfd);
            if(SSL_accept(ssl)<=0){
                SSL_free(ssl);
                close(newsockfd);
                continue;
            }

            for(int i=0;i<MAX_CLIENTS;i++){
                if(fd_clients[i]==0){
                    fd_clients[i]=newsockfd;
                    ssl_clients[i]=ssl;
                    bzero(buffer,MSG_BUFFER+NICKNAME-1);
                    //server-side nickname checking rather then from client side
                    if(SSL_read(ssl,buffer,NICKNAME-1)<=0||!is_valid_nickname(buffer)){
                        SSL_write(ssl,"invalid nickname. disconnecting...\n",35);
                        SSL_free(ssl);
                        close(newsockfd);
                        fd_clients[i]=0;
                        ssl_clients[i]=NULL;
                    }else{
                        buffer[strcspn(buffer,"\n")]='\0';
                        //if len of src > n then the rest is filled with \0
                        strncpy(nicknames[i],buffer,NICKNAME-1);
                        //better to send stuff to user that doesnt impact the actual usage
                        //from client-side app then send everythin through tcp
                        //this way its an optimization
                        //send(newsockfd,"youre successufully connected\n",30,0);
                        char temp[MSG_BUFFER+NICKNAME-1];
                        snprintf(temp,sizeof(temp),"%s connected!\n",nicknames[i]);
                        send_to_others(i,temp);
                        if(debug==1){
                            printf("new user connected: socket %d from %s:%d as '%s'\n",
                               newsockfd,inet_ntoa(cli_addr.sin_addr),ntohs(cli_addr.sin_port),nicknames[i]);
                        }
                    }
                    break;
                }
            }
        }
        for(int i=0;i<MAX_CLIENTS;i++){
            if(fd_clients[i]&&FD_ISSET(fd_clients[i],&readfds)){
                bzero(buffer,MSG_BUFFER+NICKNAME-1);
                int n=SSL_read(ssl_clients[i],buffer,MSG_BUFFER+NICKNAME-1-1-34); //-34 for nickname+": "
                if(n<=0){
                    sprintf(buffer,".quit");
                    n=5;
                }
                buffer[n]='\0';
                buffer[strcspn(buffer,"\r\n")]='\0';
                if(special_req(buffer,i,debug)==1)
                    continue;
            }
        }
    }
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
