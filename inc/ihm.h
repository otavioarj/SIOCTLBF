#ifndef IHM
#define IHM

#include <winsock2.h>
#include <WINDOWS.h>
#include <Wincrypt.h>
#include <winioctl.h>
#include <winerror.h>

#define MAX_BUFSIZE 4096		// Max length for input buffer

enum { SystemModuleInformation = 11 };

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    ULONG Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef NTSTATUS (*NtQuerySystemInformationFunc)(
    _In_      DWORD SystemInformationClass,
    _Inout_   PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
);


// Globals
extern short int displayerrflg;
extern short int pausebuff;
extern short int brute;
BOOL cont;
HCRYPTPROV   hCryptProv;
struct sockaddr_in si_opts;
extern short int quietflg;
extern short int timec;
extern short int valid;
extern short int limit;
extern short int dlimit;
extern short int stage;

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
