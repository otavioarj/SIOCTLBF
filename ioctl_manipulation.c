#include <stdio.h>
#include <stdlib.h>
#include "ioctl_manipulation.h"



// Add an IOCTL to the list ---------------------------------------------------
pIOCTLlist addIoctlList(pIOCTLlist listIoctls, DWORD ioctl, DWORD errorCode,
                        size_t minBufferLength, size_t maxBufferLength)
{

    pIOCTLlist newListIoctls;

    newListIoctls    = (pIOCTLlist)malloc(sizeof(IOCTLlist));
    if(newListIoctls == NULL)
    {
        printf("[!] malloc() error\n");
        exit(1);
    }
    newListIoctls->IOCTL     = ioctl;
    newListIoctls->errorCode = errorCode;
    newListIoctls->previous  = listIoctls;
    newListIoctls->minBufferLength = minBufferLength;
    newListIoctls->maxBufferLength = maxBufferLength;

    return newListIoctls;
}


// Get the IOCTLs list length -------------------------------------------------
int getIoctlListLength(pIOCTLlist listIoctls)
{
    int len;
    for(len = 0; listIoctls != NULL; listIoctls = listIoctls->previous, len++);
    return len;
}


// Get a given element of the IOCTLs list -------------------------------------
pIOCTLlist getIoctlListElement(pIOCTLlist listIoctls, int index)
{
    int i;
    if(index == 0)
        return listIoctls;

    for(i=1; listIoctls != NULL && i<=index; i++,
            listIoctls = listIoctls->previous);
    return listIoctls;
}


// Free the IOCTLs list -------------------------------------------------------
void freeIoctlList(pIOCTLlist listIoctls)
{
    pIOCTLlist prev;

    while(listIoctls != NULL)
    {
        prev = listIoctls->previous;
        free(listIoctls);
        listIoctls = prev;
    }

    return;
}


// Print an IOCTL code --------------------------------------------------------
void printIoctl(DWORD ioctl, DWORD errorCode)
{

    printf("\t0x%08x ", ioctl);

    if(errorCode)
        printf("- Error %d", errorCode);

    printf("\n");
    return;
}


// Print the whole list -------------------------------------------------------
void printIoctlList(pIOCTLlist listIoctls, size_t maxBufsize)
{
    pIOCTLlist currentIoctl;
    short int cnt=0;
    for(currentIoctl = listIoctls; currentIoctl != NULL;
            currentIoctl = currentIoctl->previous)
    {

        printf(" [%d] 0x%08x  \tfunction code: 0x%04x\n",cnt++,currentIoctl->IOCTL,
               (currentIoctl->IOCTL & 0x00003ffc) >> 2);
        printf("\t\ttransfer type: %s\n",transferTypeFromCode(METHOD_FROM_CTL_CODE(currentIoctl->IOCTL)));
        printf("\t\tinput bufsize: ");

        if(currentIoctl->minBufferLength == 0 &&
                currentIoctl->maxBufferLength == maxBufsize)
        {
            printf("seems not fixed... min = 0 | max = %d (0x%x) used\n",
                   maxBufsize, maxBufsize);
        }
        else if(currentIoctl->minBufferLength == currentIoctl->maxBufferLength)
        {
            printf("fixed size = %d (0x%x)", currentIoctl->minBufferLength,
                   currentIoctl->minBufferLength);
            if(currentIoctl->minBufferLength == 0)
                printf(" [Not Fuzzable]");

            printf("\n");
        }
        else
            printf("min = %d (0x%x) | max = %d (0x%x)\n",
                   currentIoctl->minBufferLength, currentIoctl->minBufferLength,
                   currentIoctl->maxBufferLength, currentIoctl->maxBufferLength);

        if(currentIoctl->errorCode)
            printf("\t\t\terror code: %d (0x%x)\n", currentIoctl->errorCode,
                   currentIoctl->errorCode);

        printf("\n");
    }
    return;
}


// Print IOCTLs codes choice menu ---------------------------------------------
void printIoctlChoice(pIOCTLlist listIoctls)
{
    pIOCTLlist currentIoctl;
    int i;

    for(currentIoctl = listIoctls, i=0;
            currentIoctl != NULL;
            currentIoctl = currentIoctl->previous, i++)
    {

        printf("\t[%d] 0x%08x \n", i, currentIoctl->IOCTL);
    }
    printf("\t[%d] Exit \n", i);
}


// Gives the name of the transfer type from its code --------------------------
//                   cf. http://msdn.microsoft.com/en-us/library/ms810023.aspx
char *transferTypeFromCode(DWORD code)
{
    switch(code)
    {
    case 0:
        return "METHOD_BUFFERED";
    case 1:
        return "METHOD_IN_DIRECT";
    case 2:
        return "METHOD_OUT_DIRECT";
    case 3:
        return "METHOD_NEITHER";
    default:
        return "";
    }
}
