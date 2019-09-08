# SIOCTLBF
## Super IOCTL Basic Fuzzer

This is an extended and rewritten version (32 & 64 bits) of the IOCTL fuzzer by [koutto](https://github.com/koutto/ioctlbf). 
Fundamentally all the test cases and the fuzzer engine was altered to match my needs of performance and resilience, e.g., the fuzzer can report the last operation before a kernel panic (a.k.a Blue Screen of Death). 

A tiny UDP client was written to stream all fuzzer output before dispatching the IOCLT. Among other changes, it has a timed and guided test case tunning, including output analysis; which can detect some kind of leaking from kernel side :P.

This fuzzer **helped me** into CVE2018-8060 and CVE2018-8061 \o/, use it with kindness!

```
   ____                   ________  _____________     ___  ___
  / ____ _____ ___ ____  /  _/ __ \/ ___/_  __/ /    / _ )/ _/
 _\ \/ // / _ / -_/ __/ _/ // /_/ / /__  / / / /__  / _  / _/
/___/\_,_/ .__\__/_/   /___/\____/\___/ /_/ /____/ /____/_/
        /_/
                                                            v1.6

[*] Usage:
 Sioctlbf.exe -d <deviceName> -i <code>/-r <code>-<code>  [-s <stage>] [-c <remote:port>] [-q <mode>] [-t <time>] [-n] [-b] [-u] [-f] [-e] [-v]

[*] Options:
    -------
    -b  Ignore most errors and buffer checking and continue anyway.
    -c  Stream (UDP) to remote:port the stdout during fuzzing.
    -d  Symbolic device name (without \\.\).
    -e  Display error codes during IOCTL scanning.
         -> Except: NOT_SUPPORTED
                    ACCESS_DENIED
                    INVALID_FUNCTION
    -f  Filter IOCTLs always successful independently of buffer length
    -h  Display this help.
    -i  IOCTL code used as reference for scanning.
    -n  Don't use NULL pointer or buffers.
    -p  Pause and hexdump if out buffer was wrote.
    -q  Quiet level: 1 - don't display hexdumps when fuzzing
                     2 - don't display any extra info
                     3 - display *only* critical/error info
    -r  IOCTL codes range (format: 00004000-00008000) to fuzz.
    -s  Only execute given stage: 1 - trivial buffer data and overflows
                                  2 - predetermined buffer data
                                  3 - random buffer data
    -t  Max time in minutes for fuzzing.
    -v  Use valid buffers address when testing buffer length


[*] Examples:
    --------
    Scanning by Function code + Transfer type bruteforce from given valid IOCTL:
     > Sioctlbf.exe -d deviceName -i 00004000

    Scanning a given IOCTL codes range (filter enabled):
     > Sioctlbf.exe -d deviceName -r 00004000-00004fff -f

    Fuzzing only a given IOCTL (quiet mode):
     > Sioctlbf.exe -d deviceName -i 00004000  -q 1

    Fuzzing only a given IOCTL (stage 3 only):
     > Sioctlbf.exe -d deviceName -i 00004000 -s 3
