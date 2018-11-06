#ifndef UTILS
#define UTILS

#include <winsock2.h>
#include <WINDOWS.h>
#include <Wincrypt.h>
#include <winioctl.h>
#include <winerror.h>
#define BUFLEN 4096  //Max length of UDP buffer


struct sockaddr_in si_opts;
extern int sckt;
extern short int quietflg;

int socket_init(char * server,int port);
char *substr(char *src, int pos, int len);


#endif // UTILS
