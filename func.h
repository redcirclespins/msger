#ifndef FUNC_H
#define FUNC_H

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct sockaddr* create_address(const char* ip,const int port);
int create_socket();

#endif
