#include<stdio.h>
#include<stdlib.h>
#include "ioctl_manipulation.h"



// Banner ---------------------------------------------------------------------
void banner() {
printf("   ____                   ________  _____________     ___  ___\n");
printf("  / ____ _____ ___ ____  /  _/ __ \\/ ___/_  __/ /    / _ )/ _/\n");
printf(" _\\ \\/ // / _ / -_/ __/ _/ // /_/ / /__  / / / /__  / _  / _/\n");
printf("/___/\\_,_/ .__\\__/_/   /___/\\____/\\___/ /_/ /____/ /____/_/\n");
printf("        /_/\n");
printf("                                                            v1.5\n\n");
}

// Globals
int sckt;


// Usage/Help message ---------------------------------------------------------
void usage(char *progName) {
	banner();
	printf("[*] Usage:\n");
	printf("  %s -d <deviceName> -i <code>/-r <code>-<code>  [-s <stage>] [-c <remote:port>] [-q <mode>] [-t <time>] [-n] [-b] [-u] [-f] [-e]\n\n",progName);
	printf("[*] Options:                                                           \n");
	printf("    -------                                                           \n");
	printf("    -b	Ignore most errors and buffer checking and continue anyway.   \n");
	printf("    -c	Stream (UDP) to remote:port the stdout during fuzzing.       \n");
	printf("    -d	Symbolic device name (without \\\\.\\).                      \n");
    printf("    -e	Display error codes during IOCTL codes scanning.             \n");
	printf("    -f 	Filter out IOCTLs with no buffer length restriction.         \n");
	printf("    -h	Display this help.                                           \n");
    printf("    -i	IOCTL code used as reference for scanning.                   \n");
   	printf("    -n	Doesn't use NULL pointer or buffers.                         \n");
   	printf("    -p	Pause and hexdump if out buffer was wrote.                   \n");
	printf("    -q	Quiet level: 1 - don't display hexdumps when fuzzing         \n");
	printf("                     2 - don't display any extra info                \n");
	printf("                     3 - display *only* critical/error info          \n");
	printf("    -r 	IOCTL codes range (format: 00004000-00008000) to fuzz.       \n");
	printf("    -s	Only execute given stage: 1 - trivial buffer overflow       \n");
    printf("                                  2 - predetermined buffer data     \n");
    printf("                                  3 - random buffer data            \n");
    printf("    -t	Max time in minutes for fuzzing.                            \n");
	printf("\n\n");
	printf("[*] Examples:                                                          \n");
	printf("    --------                                                          \n");
	printf("    Scanning by Function code + Transfer type bruteforce from given valid IOCTL:\n");
	printf("     > %s -d deviceName -i 00004000                            \n\n", progName);
	printf("    Scanning a given IOCTL codes range (filter enabled):\n");
	printf("     > %s -d deviceName -r 00004000-00004fff -f                \n\n", progName);
	printf("    Fuzzing only a given IOCTL (quiet mode):\n");
	printf("     > %s -d deviceName -i 00004000  -q 1                      \n\n", progName);
	printf("    Fuzzing only a given IOCTL (stage 3 only):\n");
	printf("     > %s -d deviceName -i 00004000 -s 3                      \n", progName);
	printf("\n");
	exit(1);
}


// Exit the program -----------------------------------------------------------
void exitProgram(pIOCTLlist listIoctls) {
	myprintf("\n[~] Exiting ...\n");
	freeIoctlList(listIoctls);
	closesocket(sckt);
	exit(1);
}


// Gives the error message corresponding to a given Win32 error code ----------
char *errorCode2String(DWORD errorCode) {

    LPVOID lpMsgBuf;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

	return lpMsgBuf;
}



void Hexdump (const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		myprintf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			myprintf(" ");
			if ((i+1) % 16 == 0) {
				myprintf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					myprintf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					myprintf("   ");
				}
				myprintf("|  %s \n", ascii);
			}
		}
	}
}

// Convert a string into hexadecimal ------------------------------------------
DWORD parseHex(char *str) {
    DWORD value = 0;

    for(;; ++str) {
		switch( *str ) {
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				value = value << 4 | (*str & 0xf);
				break;
			case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
			case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
				value = value << 4 | ( 9 + (*str & 0xf));
				break;
			default:
				return value;
		}
	}
}

