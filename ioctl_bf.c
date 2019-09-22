// System includes ------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

// Program include ------------------------------------------------------------
#include "getopt.h"
//#include "rng.c"
#include "utilities.h"

// Globals
short int displayerrflg = 0;
short int pausebuff=0;
short int quietflg=0;
short int brute=0;
short int timec=0;
short int valid=0;
short int limit=0;
short int dlimit=0;
short int stage=0;


// Main function --------------------------------------------------------------
int main(int argc, char *argv[])
{
    extern char *optarg;
    char *singleIoctl		 = NULL;
    char *rangeIoctl		 = NULL;
    char *host               = NULL;
    short int singleflg  = 0;
    short int errflg 	 = 0;
    short int filteralwaysok = 0;
    short int nonull=0;
    short int port=0;

    HANDLE deviceHandle;
    char  * deviceName=NULL;
    MYWORD  beginIoctl=0, endIoctl=0, currentIoctl=0;
    DWORD  status=0, errorCode=0;
    DWORD  nbBytes = 0;
    pIOCTLlist listIoctls 	 = NULL;
    pIOCTLlist posListIoctls = NULL;
    int choice = -1;
    short int c=0, i=0,j=0;
    time_t rawtime;
    short int ptm=0,ip[4];

    // Parse options from command-line
    while((c = getopt(argc, argv, "c:d:i:r:s:q:t:l:nph?efbv")) != -1)
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
            
        case 'l':
            limit=atoi(optarg);
            if(limit<=0)
            {
                myprintf("[-] Invalid rate:%d\n",limit);
                exit(1);
            }
            dlimit=limit;

            break;
		case 'h':
        case 'v':
            valid++;
            break;
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


    if(errflg)
        usage(argv[0]);
    else
        banner();

    if(host && socket_init(host,port))
        myprintf("[-] Can't stream to %s:%d!\n", host,port);
    else if (host)
        myprintf("[*] Streaming to %s:%d!\n", host,port);

    // Open handle to the device
    myprintf("[*] Openning handle to the device: %s \n", deviceName);
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
    myprintf("    Summary:\n");
    myprintf("    -------------------------\n");
    myprintf("    IOCTL scanning mode   : ");
    if(rangeIoctl)
        myprintf("Range mode 0x%08x - 0x%08x\n", beginIoctl, endIoctl);
    else if(singleIoctl && singleflg)
        myprintf("Single mode 0x%08x\n", beginIoctl);
    else
        myprintf("Function + transfer type bf 0x%08x - 0x%08x\n",
                 beginIoctl, endIoctl);
    myprintf("    Filter mode           : ");
    if(filteralwaysok)
        myprintf("Filtering codes that return true for all buffer sizes\n");
    else
        myprintf("Filter disabled\n");

    myprintf("    Symbolic Device Name  : %s\n", deviceName);
    if(singleIoctl)
        myprintf("    Device Type           : 0x%08x\n",
                 (beginIoctl & 0xffff0000) >> 16);
    myprintf("    Device handle         : 0x%08x\n\n", deviceHandle);

    if(singleIoctl && singleflg)
        myprintf("[~] Test given IOCTL and determine input size...\n");
    else
        myprintf("[~] Bruteforce function code + transfer type and determine input sizes...\n");
    if(nonull)
        myprintf("[~] Non-null input buffer\n");
    if(valid)
        myprintf("[~] Using valid memory address inside in-buffer\n");
    if(limit)
        myprintf("[~] Limiting the output into 1/%d messages\n",limit);

    // IOCTL code scanning
    for(currentIoctl = beginIoctl; currentIoctl<=endIoctl; currentIoctl++)
    {
        if(!nonull)
        {
            myprintf("[~] Trying null pointers\r");
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
                if((displayerrflg && errorCode != ERROR_ACCESS_DENIED && errorCode != ERROR_NOT_SUPPORTED && errorCode !=ERROR_INVALID_FUNCTION))
                    myprintf("0x%08x -> error code %03d - %s\r", currentIoctl,
                             errorCode, errorCode2String(errorCode));
                else if(!brute)
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

        listIoctls=getIoBuff_minmax(currentIoctl,deviceHandle,listIoctls);

    }
    myprintf("\n");
    if(!getIoctlListLength(listIoctls))
    {
        if(singleflg)
            myprintf("[!] The given IOCTL code seems not to be recognized by the driver !\n");
        else
            myprintf("[!] No valid IOCTL code has been found !\n");

        exit(1);

    }
    else
    {
        if(singleflg)
            myprintf("[!] The given IOCTL code is recognized by the driver !\n\n");
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
            myprintf("[*] Choice: ");
            scanf_s("%d", &choice, 3);

            if(choice < 0 || choice >= getIoctlListLength(listIoctls))
                goto exit;
        }

        posListIoctls = getIoctlListElement(listIoctls, choice);

        // Start fuzzing
        myprintf("\n");
        myprintf("[*] Fuzzing IOCTL 0x%08x     \n", posListIoctls->IOCTL);
        myprintf("   ------------------------ \n");

        // Stage 1: Check for trivial kernel overflow
        if(stage==1 || !stage)
            IoStage1(posListIoctls, deviceHandle);

        // Stage 2: Fuzzing with predetermined DWORDs
        if (stage==2 || !stage)
            IoStage2(posListIoctls, deviceHandle, ptm);

        // Stage 3: Fuzzing with fully random data
        if(stage==3 || !stage)
            IoStage3(posListIoctls, deviceHandle, ptm);

        myprintf("[0x%08x] Fuzzing finished\n",posListIoctls->IOCTL);
exit:
        myprintf("[?] Exit fuzzer? (y/n)");
        if(getch() == 'y')
            exitProgram(listIoctls);
        myprintf("\n");
    }
    return 1;
}
