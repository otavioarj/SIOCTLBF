#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "utilities.h"



/*

Utilities

*/


void getIoBuff_minmax(DWORD currentIoctl, HANDLE deviceHandle, pIOCTLlist listIoctls)
{
    // Determine min/max input buffer size
    short int j;
    DWORD nbBytes=0, status=0, errorCode=0;
    myprintf("[~] Searching min buff |[%p]\t\t\r",currentIoctl);

    for(j=4; j<MAX_BUFSIZE ; j<<=1)
    {
        status = DeviceIoControl(deviceHandle,
                                 currentIoctl,
                                 &bufInput,
                                 j,
                                 &bufOutput,
                                 j,
                                 &nbBytes,
                                 NULL);

        if(status != 0)
            listIoctls = addIoctlList(listIoctls,
                                      currentIoctl,
                                      0,
                                      j,
                                      MAX_BUFSIZE);



        if(pausebuff && nbBytes)
        {
            myprintf("[~] Out Buffer wrote:\n");
            Hexdump(bufOutput,j);
            memset(bufOutput,0, MAX_BUFSIZE);
            myprintf("[Press enter]\n");
            getchar();
        }
        nbBytes = 0;
        /*
        else {
        	// DEBUG
        	if(GetLastError() != 31)
        		myprintf("Size = %04x -> code %d\n", j, GetLastError());
        }
        */

    }
    if(!getIoctlListLength(listIoctls))
    {
         errorCode = GetLastError();
        if(displayerrflg)
            myprintf("0x%08x -> error code %03d - %s\r", currentIoctl,
                     errorCode, errorCode2String(errorCode));
    }
    else
    {

        myprintf("[~] Searching max buff |[%p]\t\t\r",currentIoctl);

        for(j=MAX_BUFSIZE; j>=listIoctls->minBufferLength; j>>=1)
        {

            status = DeviceIoControl(deviceHandle,
                                     currentIoctl,
                                     &bufInput,
                                     j,
                                     &bufOutput,
                                     j,
                                     &nbBytes,
                                     NULL);
            if(status != 0)
                listIoctls->maxBufferLength = j;
            if(pausebuff && nbBytes)
            {
                myprintf("[~] Out Buffer wrote:\n");
                Hexdump(bufOutput,j);
                memset(bufOutput,0, MAX_BUFSIZE);
                myprintf("[Press enter]\n");
                getchar();
            }
            nbBytes = 0;


        }

    }
}


void initializeJunkData()
{
    int i;
    for(i=0; i<sizeof(MYWORD); i++)
    {
        tableDwords[i] = ~0; // full word :)
        tableDwords[i] <<= i*sizeof(MYWORD);
    }
}


// Handler for the CTRL-C signal, used to stop an action without quitting -----
BOOL CtrlHandler(DWORD fdwCtrlType)
{
    switch( fdwCtrlType )
    {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
        cont = FALSE;
        return TRUE;
    default:
        return FALSE;
    }
}


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
