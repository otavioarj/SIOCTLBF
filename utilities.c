#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "utilities.h"


/*

Utilities

*/

void myprintf( char* string, ... )
{
    va_list args;
    va_start( args, string );
    char log[BUFLEN];

    if (quietflg==3 && (strstr(string, "rror") == NULL || strstr(string, "[!]") == NULL) )
    {
        va_end( args );
        return;
    }

    vprintf(string, args);
    fflush(stdout);
    if(sckt)
    {

        vsprintf(log,string,args);
        if(sendto(sckt, log, strlen(log), 0, (struct sockaddr *) &si_opts, sizeof(si_opts))==SOCKET_ERROR)
        {
            printf("[-] Error streaming, code: %d \n[-] Using StdOut only to terminal!\n",WSAGetLastError());
            sckt=0;
        }
        else
            shutdown(sckt,SD_RECEIVE); // Force UDP flush by "disabling" UDP receive operation
    }
    va_end( args );
}

char *substr(char *src, int pos, int len)
{
  char *dest = NULL;
  if (len>0) {
    dest = calloc(len+1, 1);
    if(NULL != dest) {
        strncat(dest,src+pos,len);
    }
  }
  return dest;
}


int socket_init(char * server,int port)
{

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
    {
       myprintf("[-] Can't init WinSock\n");
       return 1;
    }
    if ((sckt=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR)
    {
        sckt=0;
        myprintf("[-] Can't open socket\n");
        return 1;
    }

    memset((char *) &si_opts, 0, sizeof(si_opts));
    si_opts.sin_family = AF_INET;
    si_opts.sin_port = htons(port);

    if ((si_opts.sin_addr.S_un.S_addr = inet_addr(server)) == 0)
    {
        sckt=0;
        myprintf("[-] Can't convert address to int!\n");
        return 1;
    }
    return 0;
}
