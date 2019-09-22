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

void IoStage3(pIOCTLlist posListIoctls, HANDLE deviceHandle, short int ptm)
{
    size_t randomLength;
    DWORD nbBytes=0, status=0;
    int i;//j,c;
    time_t rawtime;
    struct tm *ltm=NULL;
    void * inter_buff=bufOutput;
    myprintf("[*] Stage 3.\n");
    myprintf("[0x%08x] Fuzzing with fully random data and buffer size...\n (Ctrl+C to STOP)\n",
             posListIoctls->IOCTL);
    myprintf("[*] This will run FOR EVER ;)\n\n");
    cont = TRUE;
    if(SetConsoleCtrlHandler((PHANDLER_ROUTINE) CtrlHandler, TRUE))
    {
        // Infinite loop. This only stops when a Ctrl+C or fuzz max time
        while(cont)
        {
            if(timec)
            {
                rawtime=time(NULL);
                ltm = localtime(&rawtime);
                //myprintf("\n[!] I %d A %d M %d   \n",ptm,ltm->tm_min,ltm->tm_min - ptm);
                if((ltm->tm_min - ptm)>=timec)
                {
                    myprintf("[!] Max fuzzing time, aborting!\n");
                    exit(1);
                }
            }
            // Choose a random length for the buffer
            randomLength = posListIoctls->minBufferLength +rand() % (1+ posListIoctls->maxBufferLength - posListIoctls->minBufferLength );

            // Fill the buffer with random data
            if(!CryptGenRandom(hCryptProv,randomLength,bufInput))
                for(i=0; i<randomLength; i++)
                    bufInput[i] = (BYTE)rand()% 0xff;

            if(quietflg<2)
              myprintf("Input buffer: %d (0x%x) bytes\r", randomLength,randomLength);
             if(!quietflg)
                Hexdump(bufInput, posListIoctls->maxBufferLength);

            if(METHOD_FROM_CTL_CODE(posListIoctls->IOCTL) == METHOD_IN_DIRECT)
                inter_buff=&bufInput;

            status = DeviceIoControl(deviceHandle,
                                     posListIoctls->IOCTL,
                                     &bufInput,
                                     randomLength,
                                     inter_buff,
                                     randomLength,
                                     &nbBytes,
                                     NULL);

            if(pausebuff && nbBytes &&  inter_buff!=&bufInput)
            {
                myprintf("[~] Out Buffer wrote:\n");
                Hexdump(bufOutput,nbBytes);
                myprintf("[Press enter]\n");
                getchar();
            }
            nbBytes=0;
            if(quietflg<2)
            {
                if(status == 0)
                    myprintf("\n [-] Error %d: %s\n", GetLastError(),
                             errorCode2String(GetLastError()));
            }

            memset(bufOutput,0,MAX_BUFSIZE);
        }
    }
    else
    {
        myprintf("[!] Error: could not set control handler.");
        exit(1);
    }
}

void IoStage2(pIOCTLlist posListIoctls, HANDLE deviceHandle, short int ptm)
{

    size_t randomLength;
    DWORD nbBytes=0, status=0;
    MYWORD fuzzData;
    int i,j,c;
    time_t rawtime;
    struct tm *ltm=NULL;
    void * inter_buff=bufOutput;

    myprintf("[*] Stage 2.\n");
    myprintf("[0x%08x] Fuzzing with predetermined WORDs\n (Ctrl+C to pass to the next step)",
             posListIoctls->IOCTL);

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
                        c++;
                    }


                    if(quietflg<2)
                    {
                        myprintf("|--> Fuzzing DWORD %d/%d with ",i, posListIoctls->maxBufferLength);
                        myprintf("0x%p",fuzzData);
                        myprintf(" (%d/%d)\r",j+1, sizeof(FuzzConstants)/sizeof(MYWORD));
                        if(!quietflg)
                         Hexdump(bufInput, i);
                    }

                    if(METHOD_FROM_CTL_CODE(posListIoctls->IOCTL) == METHOD_IN_DIRECT)
                        inter_buff=&bufInput;

                    status = DeviceIoControl(deviceHandle,
                                             posListIoctls->IOCTL,
                                             &bufInput,
                                             i,
                                             inter_buff,
                                             posListIoctls->maxBufferLength,
                                             &nbBytes,
                                             NULL);
                    if(pausebuff && nbBytes && inter_buff!=&bufInput)
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
                            myprintf("[-] Error %d: %s\n", GetLastError(),
                                     errorCode2String(GetLastError()));
                    }

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
            randomLength =  posListIoctls->minBufferLength + rand() % (1+ posListIoctls->maxBufferLength - posListIoctls->minBufferLength );

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

                    if(quietflg<2)
                     myprintf("|---> Random In-buffer %d bytes with 0x%p. (%d/%d)\r",randomLength,fuzzData,j+1, sizeof(FuzzConstants)/sizeof(MYWORD));
                    if(!quietflg)
                        Hexdump(bufInput, randomLength);

                    if(METHOD_FROM_CTL_CODE(posListIoctls->IOCTL) == METHOD_IN_DIRECT)
                        inter_buff=&bufInput;
                    status = DeviceIoControl(deviceHandle,
                                             posListIoctls->IOCTL,
                                             &bufInput,
                                             randomLength,
                                             inter_buff,
                                             posListIoctls->maxBufferLength,
                                             &nbBytes,
                                             NULL);
                    if(pausebuff && nbBytes && inter_buff!=&bufInput)
                    {
                        myprintf("[~] Out Buffer wrote:\n");
                        Hexdump(bufOutput,nbBytes);
                        myprintf("[Press enter]\n");
                        getchar();
                    }
                    nbBytes=0;
                    if(quietflg<2 && status == 0)
                        myprintf("[-] Error %d: %s\n", GetLastError(), errorCode2String(GetLastError()));
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
    myprintf("\n[*] End of Stage 2.\n\n");
}

void IoStage1(pIOCTLlist posListIoctls, HANDLE deviceHandle)
{
    BYTE *jamboBuff;
    size_t randomLength;
    DWORD nbBytes=0, status=0;
    MYWORD validAddr[2];
    int i;
    void * inter_buff=bufOutput;
    myprintf("[*] Stage 1.\n");
    if(METHOD_FROM_CTL_CODE(posListIoctls->IOCTL) != METHOD_BUFFERED || brute)
    {
        myprintf("[0x%08x] Checking for invalid addresses of in/out buffers...\n", posListIoctls->IOCTL);
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

    if(valid)
    {
        validAddr[0]=(MYWORD)&bufInput;
        validAddr[1]=GetKernelBase();

        for(i=0; i<MAX_BUFSIZE; i+=2)
            memcpy(&bufInput[i],(void*)validAddr,(2*sizeof(MYWORD)));
        //printf("Buf %p Addr %p\n",&bufInput[j],validAddr);

        myprintf("[0x%08x] Checking for valid addresses as data for in-buffer...\n", posListIoctls->IOCTL);
        if(METHOD_FROM_CTL_CODE(posListIoctls->IOCTL) != METHOD_OUT_DIRECT)
        {

            if(METHOD_FROM_CTL_CODE(posListIoctls->IOCTL) == METHOD_IN_DIRECT)
                inter_buff=&bufInput;
            status = DeviceIoControl(deviceHandle,
                                     posListIoctls->IOCTL,
                                     &bufInput,
                                     posListIoctls->maxBufferLength,
                                     inter_buff,
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
            nbBytes=0;
            memset(bufOutput,0, MAX_BUFSIZE);
        }

        myprintf("[0x%08x] Checking for valid addresses as in-buffer...\n", posListIoctls->IOCTL);
        for(i=0; i<=sizeof(validAddr); i++)
        {
            status = DeviceIoControl(deviceHandle,
                                     posListIoctls->IOCTL,
                                     i==sizeof(validAddr)?NULL:(void*)validAddr[i],
                                     sizeof(MYWORD),
                                     inter_buff,
                                     posListIoctls->maxBufferLength,
                                     &nbBytes,
                                     NULL);
            if(pausebuff && nbBytes &&  inter_buff!=&bufInput)
            {
                myprintf("[~] Out Buffer wrote:\n");
                Hexdump(bufOutput,nbBytes);
                myprintf("[Press enter]\n");
                getchar();
            }
            nbBytes=0;
            memset(bufOutput,0, MAX_BUFSIZE);

        }
    }


    myprintf("[0x%08x] Checking for trivial kernel overflows\n  |-> ...",posListIoctls->IOCTL);
    jamboBuff=(BYTE *)malloc(2*MAX_BUFSIZE);
    memset(jamboBuff, 0x41, 2*MAX_BUFSIZE);

    if(METHOD_FROM_CTL_CODE(posListIoctls->IOCTL) == METHOD_IN_DIRECT)
        inter_buff=&jamboBuff;

    for(i=1024; i<=2*MAX_BUFSIZE; i<<=1)
    {
        if(i % 0x100 == 0)
            myprintf(".");
        status = DeviceIoControl(deviceHandle,
                                 posListIoctls->IOCTL,
                                 jamboBuff,
                                 i,
                                 inter_buff,
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
    myprintf("..\n");
    myprintf("\n[*] End of Stage 1.\n\n");
    if(limit)
        limit++;
}

pIOCTLlist getIoBuff_minmax(DWORD currentIoctl, HANDLE deviceHandle, pIOCTLlist listIoctls)
{
    // Determine min/max input buffer size
    short int j;
    DWORD nbBytes=0, status=0, errorCode=0;
    MYWORD validAddr[2];

    if(valid)
    {
        validAddr[0]=(MYWORD)&bufInput;
        validAddr[1]=GetKernelBase();
        for(j=0; j<MAX_BUFSIZE; j+=2)
            memcpy(&bufInput[j],(void*)validAddr,(2*sizeof(MYWORD)));
        //printf("Buf %p Addr %p\n",&bufInput[j],validAddr);
    }


    myprintf("[~] Searching min buff |[%p]\t\t\r",currentIoctl);
    for(j=sizeof(MYWORD); j<=MAX_BUFSIZE ; j<<=1)
    {
        status = DeviceIoControl(deviceHandle,
                                 currentIoctl,
                                 &bufInput,
                                 j,
                                 &bufOutput,
                                 j,
                                 &nbBytes,
                                 NULL);

        errorCode= GetLastError();
        if(status != 0 || errorCode==0) // status !=0, but error==000, aka, The operation completed successfully.
            listIoctls = addIoctlList(listIoctls,
                                      currentIoctl,
                                      errorCode,
                                      j,
                                      MAX_BUFSIZE);
        else if(errorCode != ERROR_ACCESS_DENIED && errorCode != ERROR_NOT_SUPPORTED && errorCode !=ERROR_INVALID_FUNCTION && brute)
        {
            listIoctls = addIoctlList(listIoctls,
                                      currentIoctl,
                                      errorCode,
                                      j,
                                      MAX_BUFSIZE);
            myprintf("[%p] Brute adding min buff [%d]-> error: %03d - %s\n",currentIoctl,j,errorCode,errorCode2String(errorCode));
        }
        else if(displayerrflg)
              myprintf("[%p] Error: %03d - %s\n",currentIoctl,errorCode,errorCode2String(errorCode));

        if(pausebuff && nbBytes)
        {
            myprintf("[~] Out Buffer wrote:\n");
            Hexdump(bufOutput,j);
            memset(bufOutput,0, MAX_BUFSIZE);
            myprintf("[Press enter]\n");
            getchar();
        }
        nbBytes = 0;

        if(displayerrflg && (errorCode != ERROR_ACCESS_DENIED && errorCode != ERROR_NOT_SUPPORTED && errorCode !=ERROR_INVALID_FUNCTION))
            myprintf("[0x%08x] -> error code %03d - %s\r", currentIoctl, errorCode, errorCode2String(errorCode));
    }

    if(getIoctlListLength(listIoctls))
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
            errorCode= GetLastError();
            if(status != 0 || errorCode==0) // status !=0, but error==000, aka, The operation completed successfully.
                listIoctls->maxBufferLength = j;
            else if(errorCode != ERROR_ACCESS_DENIED && errorCode != ERROR_NOT_SUPPORTED && errorCode !=ERROR_INVALID_FUNCTION && brute)
            {
                myprintf("[%p] Brute adding max buff [%d] -> error: %03d - %s\n",currentIoctl,j,errorCode,errorCode2String(errorCode));
                listIoctls->maxBufferLength = j;
            }
             else if(displayerrflg)
              myprintf("[%p] Error: %03d - %s\n",currentIoctl,errorCode,errorCode2String(errorCode));

            if(pausebuff && nbBytes)
            {
                myprintf("[~] Out Buffer wrote:\n");
                Hexdump(bufOutput,j);
                memset(bufOutput,0, MAX_BUFSIZE);
                myprintf("[Press enter]\n");
                getchar();
            }
            nbBytes = 0;
            if(displayerrflg && (errorCode != ERROR_ACCESS_DENIED && errorCode != ERROR_NOT_SUPPORTED && errorCode !=ERROR_INVALID_FUNCTION))
                myprintf("[0x%08x] -> error code %03d - %s\r", currentIoctl, errorCode, errorCode2String(errorCode));
        }
    }
    return listIoctls;
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

    if(limit>dlimit)
    {
        if(!dlimit)
            dlimit=limit+1;
        else if(string[0]!='[' && string[1]!='[')
        {
            dlimit--;
            va_end( args );
            return;
        }
    }

    if(quietflg==2 && string[0]!='['  && string[1]!='[')
    {
        va_end( args );
        return;
    }

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

/*char *substr(char *src, int pos, int len)
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
}*/


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

MYWORD GetKernelBase()
{

    NtQuerySystemInformationFunc NtQuerySystemInformation = NULL;
    HMODULE hNtdll = NULL;
    MYWORD KernelBase = 0;
    RTL_PROCESS_MODULES ModuleInfo = { 0 };

    hNtdll = GetModuleHandle("ntdll");
    NtQuerySystemInformation = (NtQuerySystemInformationFunc)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    NtQuerySystemInformation(SystemModuleInformation, &ModuleInfo, sizeof(ModuleInfo), NULL);
    KernelBase = (MYWORD)ModuleInfo.Modules[0].ImageBase;

    return KernelBase;
}
