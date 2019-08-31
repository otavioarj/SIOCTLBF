#ifndef IHM
#define IHM

#include <winsock2.h>
#include <WINDOWS.h>
#include <Wincrypt.h>
#include <winioctl.h>
#include <winerror.h>

#define MAX_BUFSIZE 4096		// Max length for input buffer

// Globals
extern short int displayerrflg;
extern short int pausebuff;
extern short int brute;
BOOL cont;
struct sockaddr_in si_opts;
extern short int quietflg;
extern short int timec;
// Todo: buffer safe for multi-threads :P
BYTE  bufInput[MAX_BUFSIZE];
BYTE  bufOutput[MAX_BUFSIZE];


typedef struct IOCTLlist_
{
    DWORD IOCTL;
    DWORD errorCode;
    size_t minBufferLength;
    size_t maxBufferLength;
    struct IOCTLlist_ *previous;
} IOCTLlist, *pIOCTLlist;

void banner();
void usage(char *progName);
void exitProgram(pIOCTLlist listIoctls);
char *errorCode2String(DWORD errorCode);
void Hexdump(const void* data, size_t size);
DWORD parseHex(char *str);
#endif
