#ifndef UTILS
#define UTILS


#include "ioctl_manipulation.h"
#include <time.h>
#define BUFLEN 4096  //Max length of UDP buffer



#define INVALID_BUF_ADDR_ATTEMPTS	5



#ifdef _WIN64
#define MYWORD DWORD64
#warning "64 BITS"
extern MYWORD tableDwords[sizeof(MYWORD)];
extern MYWORD invalidAddresses[];
extern MYWORD FuzzConstants[];
#else
#define MYWORD DWORD
#warning "32 BITS"
extern MYWORD tableDwords[sizeof(MYWORD)];
extern MYWORD invalidAddresses[];
extern MYWORD FuzzConstants[];
#endif // _WIN64




// Functions
void myprintf( char* string, ... );
pIOCTLlist getIoBuff_minmax(DWORD currentIoctl, HANDLE deviceHandle, pIOCTLlist listIoctls);
void IoStage1(pIOCTLlist posListIoctls, HANDLE deviceHandle);
int socket_init(char * server,int port);
//char *substr(char *src, int pos, int len);
void initializeJunkData();
BOOL CtrlHandler(DWORD fdwCtrlType);
MYWORD GetKernelBase();

#endif // UTILS
