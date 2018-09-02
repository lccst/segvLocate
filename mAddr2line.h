#ifndef __MADDR2LINE_H__
#define __MADDR2LINE_H__

typedef struct __MADDR2LINE
{
	bfd			*abfd;
	int 		(*Addr2line)(struct __MADDR2LINE* mal, void *addr, char *outFilename, 
								char *outFuncname, unsigned int *outLine);
}MADDR2LINE;

void MAddr2line_Release(MADDR2LINE** mal);
MADDR2LINE *MAddr2line_Init(char *filename);

#endif