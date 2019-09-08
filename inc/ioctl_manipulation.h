#ifndef IOMAN
#define IOMAN

#include "ihm.h"

//#define DEVICE_TYPE_FROM_CTL_CODE(ctrlCode)   (((ULONG)(ctrlCode & 0xffff0000)) >> 16)
#define METHOD_FROM_CTL_CODE(ctrlCode)        ((ULONG)(ctrlCode & 3))



/*

IOCTLs list manipulation functions


  IOCTL code specifications:
  -------------------------

  According to winioctl.h:

   IOCTL's are defined by the following bit layout.
 [Common |Device Type|Required Access|Custom|Function Code|Transfer Type]
   31     30       16 15          14  13   12           2  1            0

   Common          - 1 bit.  This is set for user-defined
                     device types.
   Device Type     - This is the type of device the IOCTL
                     belongs to.  This can be user defined
                     (Common bit set).  This must match the
                     device type of the device object.
   Required Access - FILE_READ_DATA, FILE_WRITE_DATA, etc.
                     This is the required access for the
                     device.
   Custom          - 1 bit.  This is set for user-defined
                     IOCTL's.  This is used in the same
                     manner as "WM_USER".
   Function Code   - This is the function code that the
                     system or the user defined (custom
                     bit set)
   Transfer Type   - METHOD_IN_DIRECT, METHOD_OUT_DIRECT,
                     METHOD_NEITHER, METHOD_BUFFERED, This
                     the data transfer method to be used.


  Buffer specifications:
  ---------------------

Input Size   =  Parameters.DeviceIoControl.InputBufferLength
Output Size  =  Parameters.DeviceIoControl.OutputBufferLength

  - METHOD_BUFFERED:
		Input Buffer = Irp->AssociatedIrp.SystemBuffer
		Ouput Buffer = Irp->AssociatedIrp.SystemBuffer

		input & output buffers use the same location, so the buffer allocated
		by the I/O manager is the size of the larger value (output vs. input).

  - METHOD_X_DIRECT:
		Input Buffer = Irp->AssociatedIrp.SystemBuffer
		Ouput Buffer = Irp->MdlAddress

		the INPUT buffer is passed in using "BUFFERED" implementation. The
		output buffer is passed in using a MDL (DMA). The difference between
		"IN" and "OUT" is that with "IN", you can use the output buffer to
		pass in data! The "OUT" is only used to return data.

  - METHOD_NEITHER:
		Input Buffer = Parameters.DeviceIoControl.Type3InputBuffer
		Ouput Buffer = Irp->UserBuffer

		input & output buffers sizes may be different. The I/O manager does not
		provide any system buffers or MDLs. The IRP supplies the user-mode
		virtual addresses of the input and output buffer

*/


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
