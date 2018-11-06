


// System includes ------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <time.h>


// Program include ------------------------------------------------------------
#include "getopt.h"
//#include "rng.c"
#include "ioctl_manipulation.h"
#include "ihm.h"
#include "utilities.h"

#ifdef _WIN64
#define MYWORD DWORD64
#warning "64 BITS"
#else
#define MYWORD DWORD
#warning "32 BITS"
#endif // _WIN64

// Parameters -----------------------------------------------------------------
#define MAX_BUFSIZE 4096		// Max length for input buffer
#define INVALID_BUF_ADDR_ATTEMPTS	5

// Junk data used for fuzzing -------------------------------------------------
MYWORD tableDwords[sizeof(MYWORD)];

int sckt=0;
short int quietflg=0;

#ifdef _WIN64
MYWORD invalidAddresses[] = { 0xFFFFFFFF00000000, 0x0000000010000,0x0};
#else
MYWORD invalidAddresses[] = { 0xFFFF0000, 0x00001000, 0x0};
#endif // _WIN64

BOOL cont;

// Initialize junk data -------------------------------------------------------
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


// Main function --------------------------------------------------------------
int main(int argc, char *argv[])
{


    extern char *optarg;
    //char *deviceSymbolicName = NULL;
    char *singleIoctl		 = NULL;
    char *rangeIoctl		 = NULL;
    char *host               = NULL;
    short int singleflg  = 0;
    short int errflg 	 = 0;
    short int displayerrflg = 0;
    short int filteralwaysok = 0;
    short int brute=0;
    short int nonull=0;
    short int stage=0;
    short int pausebuff=0;
    short int port=0;
    short int timec=0;
    HANDLE deviceHandle;
    char  * deviceName=NULL; // "\\\\.\\";
    MYWORD  beginIoctl=0, endIoctl=0, currentIoctl=0;
    DWORD  status=0, errorCode=0;
    DWORD  nbBytes = 0;

    pIOCTLlist listIoctls 	 = NULL;
    pIOCTLlist posListIoctls = NULL;

    int choice = -1;
    short int c=0, i=0,j=0;
    MYWORD fuzzData;

    BYTE  bufInput[MAX_BUFSIZE];
    BYTE  bufOutput[MAX_BUFSIZE];
    size_t randomLength;
    HCRYPTPROV   hCryptProv;
    time_t rawtime;
    struct tm *ltm=NULL;
    short int ptm=0,ip[4];



#ifdef _WIN64
    MYWORD FuzzConstants[] = {	0x00000000, 0x00000001, 0x00000004, 0xFFFFFFFFFFFFFFFF,
                                0x0000000010000000, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFF0,
                                0xFFFFFFFFFFFFFFFC, 0x7000000000000000, 0x7FFEFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
                                0x8000000000000000,0x4141414141414141, 0x0041004100410041,(MYWORD)tableDwords
                             };
#else

    MYWORD FuzzConstants[] = {	0x00000000, 0x00000001, 0x00000004, 0xFFFFFFFF,
                                0x00001000, 0xFFFF0000, 0xFFFFFFFE, 0xFFFFFFF0,
                                0xFFFFFFFC, 0x70000000, 0x7FFEFFFF, 0x7FFFFFFF,
                                0x80000000, 0x41414141, 0x00410041, (DWORD)tableDwords
                             };
#endif // _WIN64


    // Parse options from command-line
    while((c = getopt(argc, argv, "c:d:i:r:s:q:t:nph?efb")) != -1)
    {
        switch(c)
        {
        case 'd':
            deviceName= malloc(strlen(optarg)+5);
            strcpy(deviceName,"\\\\.\\");
            strncat(deviceName, optarg,strlen(optarg));
            break;
        case 'c':
            host=malloc(16);
            if(sscanf(optarg,"%d.%d.%d.%d:%d",&ip[0],&ip[1],&ip[2],&ip[3],&port)==EOF)
                errflg++;
            else
                sprintf(host,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
            //printf("O:%s| H: %s P:%d\n",optarg,host,port);
            break;
        case 'i':
            if(rangeIoctl)
                errflg++;
            else
            {
                singleIoctl = optarg;
                singleflg = 1;
            }
            break;
        case 'r':
            if(singleIoctl)
                errflg++;
            else
                rangeIoctl = optarg;
            break;
        case 's':
            stage =atoi(optarg);
            if(stage <1 || stage >3)
            {
                myprintf("[-] Invalid stage number: %d \n",stage);
                exit(1);
            }
            break;
        case 'q':
            quietflg =atoi(optarg);
            if(quietflg <1 || quietflg >3)
            {
                myprintf("[-] Invalid quiet flag: %d \n",quietflg);
                exit(1);
            }
            break;
        case 't':
            timec =atoi(optarg);
            rawtime = time(NULL);
            if(timec <1 || rawtime <1)
            {
                myprintf("[-] Invalid time: %d \n",timec);
                exit(1);
            }
            ptm = (localtime(&rawtime))->tm_min;
            break;
        case 'e':
            displayerrflg++;
            break;
        case 'f':
            filteralwaysok++;
            break;
        case 'b':
            brute++;
            break;
        case 'n':
            nonull++;
            break;
        case 'p':
            pausebuff++;
            break;
        case 'h':
        case '?':
            errflg++;
        }
    }
    initializeJunkData();

    // Check & parse options from command line
    if(deviceName == NULL || (rangeIoctl == NULL && singleIoctl == NULL))
        errflg++;

    if(!errflg)
    {
        // IOCTL range mode
        if(rangeIoctl)
        {
            if(strchr(rangeIoctl, '-') == NULL)
                errflg++;
            else
            {
                beginIoctl 	= (MYWORD)parseHex(strtok(rangeIoctl, "-"));
                endIoctl	= (MYWORD)parseHex(strtok(NULL, "-"));
                if(endIoctl < beginIoctl)
                    errflg++;
            }
        }
        // Function code + Transfer type (14 lowest bits) bruteforce mode
        else if(singleIoctl && !singleflg)
        {
            beginIoctl = (MYWORD)parseHex(singleIoctl) & 0xffffc000;
            endIoctl   = ((MYWORD)parseHex(singleIoctl) & 0xffffc000) | 0x00003fff;
        }
        // Single IOCTL mode
        else
        {
            beginIoctl 	= (MYWORD)parseHex(singleIoctl);
            endIoctl	= beginIoctl;
        }

    }


    // Print usage if necessary
    if(errflg)
        usage(argv[0]);
    else
        banner();

    if(host && socket_init(host,port))
        myprintf("[-] Can't stream to %s:%d!\n", host,port);
    else if (host)
        myprintf("[*] Streaming to %s:%d!\n", host,port);



    // Open handle to the device
    myprintf("[*] Open handle to the device %s ... \n", deviceName);
    deviceHandle = CreateFile((HANDLE)deviceName,
                              GENERIC_READ | GENERIC_WRITE,
                              0,
                              NULL,
                              OPEN_EXISTING,
                              0,
                              NULL);

    if(deviceHandle == INVALID_HANDLE_VALUE)
    {
        myprintf("[-] Error code: %d\n%s\n", GetLastError(),
                 errorCode2String(GetLastError()));
        exit(1);
    }


    if(!CryptAcquireContext(&hCryptProv,NULL,NULL,PROV_RSA_AES,0))
    {
        myprintf("[-] Can't get a WinCrypt provider!\n");
        exit(1);
    }
    srand(time(NULL)); // getting a internal seed :)
    memset(bufInput, nonull?0x41:0, MAX_BUFSIZE);
    memset(bufOutput,0, MAX_BUFSIZE);


    // Print summary
    myprintf("  Summary                             	\n");
    myprintf("  -------								\n");
    myprintf("  IOCTL scanning mode 	: ");
    if(rangeIoctl)
        myprintf("Range mode 0x%08x - 0x%08x\n", beginIoctl, endIoctl);
    else if(singleIoctl && singleflg)
        myprintf("Single mode 0x%08x\n", beginIoctl);
    else
        myprintf("Function + transfer type bf 0x%08x - 0x%08x\n",
                 beginIoctl, endIoctl);
    myprintf("  Filter mode           : ");
    if(filteralwaysok)
        myprintf("Filter codes that return true for all buffer sizes\n");
    else
        myprintf("Filter disabled\n");

    myprintf("  Symbolic Device Name  : %s\n", deviceName);
    if(singleIoctl)
        myprintf("  Device Type    	: 0x%08x\n",
                 (beginIoctl & 0xffff0000) >> 16);
    myprintf("  Device handle         : 0x%08x\n", deviceHandle);
    myprintf("\n");


    // IOCTL code scanning
    if(singleIoctl && singleflg)
        myprintf("[~] Test given IOCTL and determine input size...\n");
    else
        myprintf("[~] Bruteforce function code + transfer type and determine "
                 "input sizes...\n");


    i = 0;
    if(nonull)
        myprintf("[~] Non-null input buffer\n");

    for(currentIoctl = beginIoctl; currentIoctl<=endIoctl; currentIoctl++)
    {

        /*	if(!singleflg && !displayerrflg && currentIoctl % 0x400 == 0)
        		myprintf(".");
        		*/

        // DeviceIoControl: if the operation completes successfully, the
        // return value is nonzero

        if(!nonull)
        {


            myprintf("[~] Trying null pointers\n");
            status = DeviceIoControl(deviceHandle,
                                     currentIoctl,
                                     NULL,
                                     0,
                                     NULL,
                                     0,
                                     &nbBytes,
                                     NULL);

            // No further tests for the current IOCTL if the operation fails with
            // one of the following error codes:
            // - ERROR_INVALID_FUNCTION		0x1
            // - ERROR_ACCESS_DENIED		0x5
            // - ERROR_NOT_SUPPORTED		0x50
            // cf. winerror.h

            if(status == 0)
            {
                errorCode = GetLastError();

                // -- DEBUG
                //if(errorCode != 87)
                if(displayerrflg)
                {
                    myprintf("0x%08x -> error code %03d - %s\r", currentIoctl,
                             errorCode, errorCode2String(errorCode));
                }

                //myprintf("0x%08x -> code %d\n", currentIoctl, errorCode);
                // errorCode == ERROR_INVALID_FUNCTION ||
                if((errorCode == ERROR_ACCESS_DENIED    ||
                        errorCode == ERROR_NOT_SUPPORTED || errorCode==0x87)&& !brute)
                    continue;
            }
        }
        // Filter out IOCTLs that always return status != 0
        if(filteralwaysok)
        {
            status = DeviceIoControl(deviceHandle,
                                     currentIoctl,
                                     &bufInput,
                                     MAX_BUFSIZE,
                                     &bufOutput,
                                     MAX_BUFSIZE,
                                     &nbBytes,
                                     NULL);
            if(status != 0)
                for(j=0; j<4 && status != 0; j++)
                {
                    status = DeviceIoControl(deviceHandle,
                                             currentIoctl,
                                             &bufInput,
                                             j,
                                             &bufOutput,
                                             j,
                                             &nbBytes,
                                             NULL);


                    if(status == 0)
                        myprintf("0x%08x (size %d) -> error code %03d \r", currentIoctl, j, GetLastError());
                    else
                        myprintf("0x%08x (size %d) -> status != 0 \r", currentIoctl, j);
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
            if(j == 4)
                //myprintf("Skip 0x%08x\n", currentIoctl);
                continue;
        }

        // Determine min/max input buffer size
        myprintf("[~] Searching min buff\n");

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
            {
                listIoctls = addIoctlList(listIoctls,
                                          currentIoctl,
                                          0,
                                          j,
                                          MAX_BUFSIZE);
                i++;


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
        if(!i)
        {
            if(displayerrflg)
                myprintf("0x%08x -> error code %03d - %s\r", currentIoctl,
                         errorCode, errorCode2String(errorCode));
        }


        // Ok, the min buffer size has been found. Let's find the max size
        else
        {

            myprintf("[~] Searching max buff\n");

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
            if(!i)
                if(displayerrflg)
                    myprintf("0x%08x -> error code %03d - %s\r", currentIoctl,
                             errorCode, errorCode2String(errorCode));


            /*
            else {
            	// If we're here, it means no min input buffer size has been found
            	// DEBUG -----
            	myprintf("No min bufsize found for IOCTL 0x%08x\n", currentIoctl);
            	//listIoctls = addIoctlList(listIoctls, currentIoctl,
            	//GetLastError(), 0, MAX_BUFSIZE);
            	//i++;
            }
            */
        }
    }
    myprintf("\n");
    if(i == 0)
    {
        if(singleflg)
            myprintf("[!] Given IOCTL code seems not to be recognized by the driver !\n");
        else
            myprintf("[!] No valid IOCTL code has been found !\n");
        exit(1);
    }
    else
    {
        if(singleflg)
            myprintf("[!] Given IOCTL code is recognized by the driver !\n\n");
        else
            myprintf("[+] %d valid IOCTL have been found\n\n", i);
    }


    // Fuzzing IOCTL buffer
    while(1)
    {

        // Choice of the IOCTL to fuzz
        myprintf("  Valid IOCTLs found \n");
        myprintf("  ------------------ \n");
        printIoctlList(listIoctls, MAX_BUFSIZE);
        myprintf("\n");

        if(singleflg &&  getIoctlListLength(listIoctls)==1)
            choice  = 0;
        else
        {
            myprintf("[?] Choose an IOCTL to fuzz...\n");
            printIoctlChoice(listIoctls);
            myprintf("Choice : ");
            scanf_s("%d", &choice, 3);

            if(choice < 0 || choice >= getIoctlListLength(listIoctls))
                continue;
        }


        posListIoctls = getIoctlListElement(listIoctls, choice);

        // Start fuzzing
        myprintf("\n");
        myprintf("[*] Fuzzing IOCTL 0x%08x     \n", posListIoctls->IOCTL);
        myprintf("   ------------------------ \n");


        // --------------------------------------------------------------------
        // Stage 1: Check for invalid addresses of buffer
        // (for method != METHOD_BUFFERED)
        if((posListIoctls->IOCTL & 0x00000003) != 0 || brute)
        {
            myprintf("[0x%08x] Checking for invalid addresses of in/out buffers...\n",
                     posListIoctls->IOCTL);

            for(i=0; i<=INVALID_BUF_ADDR_ATTEMPTS; i++)
            {
                // Choose a random length for the buffer
                randomLength =   posListIoctls->minBufferLength +rand() % (1+ posListIoctls->maxBufferLength - posListIoctls->minBufferLength );
                // getrand(posListIoctls->minBufferLength,posListIoctls->maxBufferLength);

                status = DeviceIoControl(deviceHandle,
                                         posListIoctls->IOCTL,
                                         (LPVOID)invalidAddresses[i>sizeof(invalidAddresses)?sizeof(invalidAddresses):i],
                                         randomLength,
                                         (LPVOID)invalidAddresses[i>sizeof(invalidAddresses)?sizeof(invalidAddresses):i],
                                         randomLength,
                                         &nbBytes,
                                         NULL);
                // Sleep(SLEEP_TIME);
            }


        }


        // --------------------------------------------------------------------
        // Stage 2: Check for trivial kernel overflow
        if(stage==1 || !stage)
        {

            myprintf("[0x%08x] Checking for trivial kernel overflows\n|-> [...",
                     posListIoctls->IOCTL);


            memset(bufInput, 0x41, MAX_BUFSIZE);
            for(i=0x100; i<=MAX_BUFSIZE; i+=0x100)
            {
                if(i % 0x100 == 0)
                    myprintf(".");
                status = DeviceIoControl(deviceHandle,
                                         posListIoctls->IOCTL,
                                         &bufInput,
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
            }

            myprintf("]\n[*] End of Stage 1.\n");
        }


        // --------------------------------------------------------------------
        // Stage 3: Fuzzing with predetermined DWORDs
        if (stage==2 || !stage)
        {
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
                                memset(bufOutput,0, MAX_BUFSIZE);
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
        // --------------------------------------------------------------------
        // Stage 4: Fuzzing with fully random data
        if(stage==3 || !stage)
        {
            myprintf("\n\n[0x%08x] Fuzzing with fully random data and buffer size...\n",
                     posListIoctls->IOCTL);
            myprintf("(Ctrl+C to STOP)\n[*] This will run FOR EVER ;)\n\n");
            cont = TRUE;
            if(SetConsoleCtrlHandler((PHANDLER_ROUTINE) CtrlHandler, TRUE))
            {
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

                    if(!quietflg)
                        Hexdump(bufInput, posListIoctls->maxBufferLength);
                    else if(quietflg<2)
                    {
                        myprintf("Input buffer: %d (0x%x) bytes\r", randomLength,randomLength);

                    }

                    status = DeviceIoControl(deviceHandle,
                                             posListIoctls->IOCTL,
                                             &bufInput,
                                             randomLength,
                                             &bufOutput,
                                             randomLength,
                                             &nbBytes,
                                             NULL);

                    if(pausebuff && nbBytes)
                    {
                        myprintf("[~] Out Buffer wrote:\n");
                        Hexdump(bufOutput,nbBytes);
                        memset(bufOutput,0, MAX_BUFSIZE);
                        myprintf("[Press enter]\n");
                        getchar();
                    }

                    if(quietflg<2)
                    {
                        if(status == 0)
                            myprintf("\nError %d: %s\n", GetLastError(),
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


        // --------------------------------------------------------------------



        myprintf("[0x%08x] Fuzzing finished\n",posListIoctls->IOCTL);
        myprintf("[?] Continue ? (y/n)");
        if(getch() != 'y')
            exitProgram(listIoctls);
        myprintf("\n");
    }
    myprintf("[*] All fuzzing test finished\n");
    return 0;
}
