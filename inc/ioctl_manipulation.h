#ifndef IOMAN
#define IOMAN

#include "ihm.h"
extern int sckt;
pIOCTLlist addIoctlList(pIOCTLlist listIoctls, DWORD ioctl, DWORD errorCode,
                        size_t minBufferLength, size_t maxBufferLength);
int getIoctlListLength(pIOCTLlist listIoctls);
pIOCTLlist getIoctlListElement(pIOCTLlist listIoctls, int index);
void freeIoctlList(pIOCTLlist listIoctls);
void printIoctl(DWORD ioctl, DWORD errorCode);
void printIoctlList(pIOCTLlist listIoctls, size_t maxBufsize);
void printIoctlChoice(pIOCTLlist listIoctls);
char *transferTypeFromCode(DWORD code);

#endif // IOMAN
