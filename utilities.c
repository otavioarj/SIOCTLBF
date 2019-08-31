#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "utilities.h"



// Globals

#ifdef _WIN64
MYWORD tableDwords[sizeof(MYWORD)];
MYWORD invalidAddresses[] = { 0xFFFFFFFF00000000, 0x0000000010000,0x0};
MYWORD FuzzConstants[] = {	0x00000000, 0x00000001, 0x00000004, 0xFFFFFFFFFFFFFFFF,
                            0x0000000010000000, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFF0,
                            0xFFFFFFFFFFFFFFFC, 0x7000000000000000, 0x7FFEFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
                            0x8000000000000000,0x4141414141414141, 0x0041004100410041,(MYWORD)tableDwords
                         };
#else
MYWORD tableDwords[sizeof(WORD)];
MYWORD invalidAddresses[] = { 0xFFFF0000, 0x00001000, 0x0};
MYWORD FuzzConstants[] = {	0x00000000, 0x00000001, 0x00000004, 0xFFFFFFFF,
                            0x00001000, 0xFFFF0000, 0xFFFFFFFE, 0xFFFFFFF0,
                            0xFFFFFFFC, 0x70000000, 0x7FFEFFFF, 0x7FFFFFFF,
                            0x80000000, 0x41414141, 0x00410041, (DWORD)tableDwords
                         };
#endif // _WIN64



/*

Utilities

*/


void IoStage2(pIOCTLlist posListIoctls, HANDLE deviceHandle, short int ptm)
{

    size_t randomLength;
    DWORD nbBytes=0, status=0, errorCode=0;
    MYWORD fuzzData;
    int i,j,c;
    time_t rawtime;
    struct tm *ltm=NULL;

    myprintf("\n[0x%08x] Fuzzing with predetermined DWORDs\n",
             posListIoctls->IOCTL);
    myprintf("(Ctrl+C to pass to the next step)\n");
    cont = TRUE;
    if(SetConsoleCtrlHandler((PHANDLER_ROUTINE) CtrlHandler, TRUE))
    {

        // Fill the buffer with data from FuzzConstants (1 DWORD after 1)
        for(i=posListIoctls->minBufferLength; cont && i<=posListIoctls->maxBufferLength; i+=sizeof(MYWORD))
        {

            if(timec)
            {
                rawtime=time(NULL);
                ltm = localtime(&rawtime);
                if((ltm->tm_min - ptm)>=timec)
                {
                    myprintf("[!] Max fuzzing time, aborting!\n");
                    exit(1);
                }
            }
            myprintf("=> Fuzzing buffer size %d/%d\r",i, posListIoctls->maxBufferLength);

            for(j=0; cont && j<(sizeof(FuzzConstants)/sizeof(MYWORD)); j++)
            {
                c=0;
                do
                {
                    // Choose an element into FuzzConstants
                    if(j<15)
                    {
                        fuzzData=FuzzConstants[j];
                        memset(bufInput,FuzzConstants[j],i);
                    }
                    else
                    {
                        memset(bufInput,((MYWORD *)FuzzConstants[j])[c],i);
                        fuzzData=((MYWORD *)FuzzConstants[j])[c];
                    }


                    if(!quietflg)
                        Hexdump(bufInput, i);
                    else if(quietflg<2)
                    {
                        myprintf("|--> Fuzzing DWORD %d/%d with ",i, posListIoctls->maxBufferLength);
                        myprintf("0x%p",fuzzData);
                        myprintf(" (%d/%d)\r",j+1, sizeof(FuzzConstants)/sizeof(MYWORD));
                    }

                    status = DeviceIoControl(deviceHandle,
                                             posListIoctls->IOCTL,
                                             &bufInput,
                                             i,
                                             &bufOutput,
                                             posListIoctls->maxBufferLength,
                                             &nbBytes,
                                             NULL);
                    if(pausebuff && nbBytes)
                    {
                        myprintf("\n[~] Out Buffer wrote:\n");
                        Hexdump(bufOutput, nbBytes);
                        myprintf("[Press enter]\n");
                        getchar();
                    }
                    nbBytes = 0;

                    if(quietflg<2)
                    {
                        if(status == 0)
                            myprintf("\nError %d: %s\n", GetLastError(),
                                     errorCode2String(GetLastError()));
                    }
                    c++;
                    memset(bufOutput,0,MAX_BUFSIZE);
                }
                while(j >14 && c<sizeof(MYWORD));
            }
        }


        myprintf("\n|--> Filling buffer with random[%d] size\n",2*(1+posListIoctls->maxBufferLength - posListIoctls->minBufferLength));
        for(i=0; cont && i<2*(1+posListIoctls->maxBufferLength - posListIoctls->minBufferLength); i++)
        {
            if(timec)
            {
                rawtime=time(NULL);
                ltm = localtime(&rawtime);
                if((ltm->tm_min - ptm)>=timec)
                {
                    myprintf("[!] Max fuzzing time, aborting!\n");
                    exit(1);
                }
            }
            // Choose a random length for the buffer
            randomLength =  posListIoctls->minBufferLength + rand() % (1+ posListIoctls->maxBufferLength - posListIoctls->minBufferLength );//getrand(posListIoctls->minBufferLength,posListIoctls->maxBufferLength);

            // Fill the whole buffer with data from FuzzConstants
            // memset(bufInput, 0x00, MAX_BUFSIZE);
            for(j=0; cont && j<(sizeof(FuzzConstants)/sizeof(MYWORD)); j++)
            {
                c=0;
                do
                {
                    // Choose an element into FuzzConstants
                    if(j<15)
                    {
                        memset(bufInput,FuzzConstants[j],randomLength);
                        fuzzData=FuzzConstants[j];
                    }
                    else
                    {
                        memset(bufInput,((MYWORD *)FuzzConstants[j])[c],randomLength);
                        fuzzData=((MYWORD *)FuzzConstants[j])[c];
                    }

                    if(!quietflg)
                        Hexdump(bufInput, randomLength);
                    else if(quietflg<2)
                        myprintf("|---> Random In-buffer %d bytes with 0x%p. (%d/%d)\r",randomLength,fuzzData,j+1, sizeof(FuzzConstants)/sizeof(MYWORD));


                    status = DeviceIoControl(deviceHandle,
                                             posListIoctls->IOCTL,
                                             &bufInput,
                                             randomLength,
                                             &bufOutput,
                                             posListIoctls->maxBufferLength,
                                             &nbBytes,
                                             NULL);
                    if(pausebuff && nbBytes)
                    {
                        myprintf("[~] Out Buffer wrote:\n");
                        Hexdump(bufOutput,nbBytes);
                        myprintf("[Press enter]\n");
                        getchar();
                    }

                    if(quietflg<2)
                        if(status == 0)
                            myprintf("\nError %d: %s\n", GetLastError(), errorCode2String(GetLastError()));
                    c++;
                    memset(bufOutput,0,MAX_BUFSIZE);
                }
                while(j >14 && c<sizeof(MYWORD));
            }

            //Sleep(SLEEP_TIME);
        }

    }
    else
    {
        myprintf("[!] Error: could not set control handler.");
        exit(1);
    }
    myprintf("\n[*] End of Stage 2.\n");
}

void IoStage1(pIOCTLlist posListIoctls, HANDLE deviceHandle)
{
    BYTE *jamboBuff;
    size_t randomLength;
    DWORD nbBytes=0, status=0, errorCode=0;
    int i;

// Check for invalid addresses of buffer
    // (for method != METHOD_BUFFERED)
    if((posListIoctls->IOCTL & 0x00000003) != 0 || brute)
    {
        myprintf("[0x%08x] Checking for invalid addresses of in/out buffers...\n",
                 posListIoctls->IOCTL);

        for(i=0; i<=INVALID_BUF_ADDR_ATTEMPTS; i++)
        {
            // Choose a random length for the buffer
            randomLength =   posListIoctls->minBufferLength +rand() % (1+ posListIoctls->maxBufferLength - posListIoctls->minBufferLength );
            status = DeviceIoControl(deviceHandle,
                                     posListIoctls->IOCTL,
                                     (LPVOID)invalidAddresses[i>sizeof(invalidAddresses)?sizeof(invalidAddresses)-1:i],
                                     randomLength,
                                     (LPVOID)invalidAddresses[i>sizeof(invalidAddresses)?sizeof(invalidAddresses)-1:i],
                                     randomLength,
                                     &nbBytes,
                                     NULL);
        }
    }
    myprintf("[0x%08x] Checking for trivial kernel overflows\n|-> [...",
             posListIoctls->IOCTL);

    jamboBuff=(BYTE *)malloc(2*MAX_BUFSIZE);
    memset(jamboBuff, 0x41, 2*MAX_BUFSIZE);
    for(i=1024; i<=2*MAX_BUFSIZE; i<<=1)
    {
        if(i % 0x100 == 0)
            myprintf(".");
        status = DeviceIoControl(deviceHandle,
                                 posListIoctls->IOCTL,
                                 jamboBuff,
                                 i,
                                 &bufOutput,
                                 i,
                                 &nbBytes,
                                 NULL);
        if(pausebuff && nbBytes)
        {
            myprintf("[~] Out Buffer wrote:\n");
            Hexdump(bufOutput,i);
            memset(bufOutput,0, MAX_BUFSIZE);
            myprintf("[Press enter]\n");
            getchar();
        }
        nbBytes = 0;
        memset(bufOutput,0, MAX_BUFSIZE);
    }
    free(jamboBuff);
    myprintf("]\n[*] End of Stage 1.\n");
}

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
        else
        {
            errorCode= GetLastError();
            if(errorCode != ERROR_ACCESS_DENIED && errorCode != ERROR_NOT_SUPPORTED && errorCode !=ERROR_INVALID_FUNCTION && brute)
            {
                listIoctls = addIoctlList(listIoctls,
                                          currentIoctl,
                                          0,
                                          j,
                                          MAX_BUFSIZE);
                myprintf("[+] Brute adding min buff [%p]-> error: %03d - %s\n",currentIoctl,errorCode,errorCode2String(errorCode));
            }

        }



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
        if(displayerrflg && (errorCode != ERROR_ACCESS_DENIED && errorCode != ERROR_NOT_SUPPORTED && errorCode !=ERROR_INVALID_FUNCTION))
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
            else
            {
                errorCode= GetLastError();
                if(errorCode != ERROR_ACCESS_DENIED && errorCode != ERROR_NOT_SUPPORTED && errorCode !=ERROR_INVALID_FUNCTION && brute)
                {
                    listIoctls = addIoctlList(listIoctls,
                                              currentIoctl,
                                              0,
                                              j,
                                              MAX_BUFSIZE);
                    myprintf("[+] Brute adding max buff [%p]-> error: %03d - %s\n",currentIoctl,status,errorCode2String(status));
                }
            }
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
    if (len>0)
    {
        dest = calloc(len+1, 1);
        if(NULL != dest)
        {
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
