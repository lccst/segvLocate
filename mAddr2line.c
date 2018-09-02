#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <execinfo.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>

#include <dlfcn.h>

#include "bfd.h"
#include "mAddr2line.h"

#if __WORDSIZE == 64
	#define OFFSET 8
#else
	#define OFFSET 4
#endif
	

static int MAddr2line_Addr2line(MADDR2LINE* mal, void *addr, char *outFilename, char *outFuncname, unsigned int *outLine)
{
	bfd_vma 	pc;
	bfd_vma 	vma;
	bfd_size_type size;

	asection *sect;
	bfd_boolean found = 0;
	asymbol **syms; 
	const char *filename;
	const char *funcname;
	
	static char isFirstAddr = 1;
	
	if(isFirstAddr){
		pc = (bfd_vma)(addr);	
	}else
		pc = (bfd_vma)(addr-OFFSET);
	for (sect = mal->abfd->sections; sect != NULL; sect = sect->next){
		if ((bfd_get_section_flags(mal->abfd, sect) & SEC_ALLOC) == 0)
			continue;

		vma = bfd_get_section_vma(mal->abfd, sect);
		if (pc < vma)
			continue;

		size = bfd_get_section_size(sect);
		if (pc >= vma + size)
			continue;
		found = bfd_find_nearest_line(mal->abfd, sect, syms, pc - vma,
						&filename, &funcname, outLine);
	}

	if(found){
		strcpy(outFilename, filename);
		strcpy(outFuncname, funcname);
		isFirstAddr = 0;
	}
	
	return found;
}


void MAddr2line_Release(MADDR2LINE** mal)
{
	if(NULL!=*mal){
		if(NULL!=(*mal)->abfd)
			bfd_close((*mal)->abfd);
		
		free(*mal);
		*mal = NULL;
	}
}

MADDR2LINE *MAddr2line_Init(char *filename)
{
	int status = 0;
	MADDR2LINE *mAddr2line = NULL;
	char **matching = NULL;
	
	mAddr2line = (MADDR2LINE*)malloc(sizeof(MADDR2LINE));
	if(NULL == mAddr2line){
		status = -1;
		goto error;
	}
	
	mAddr2line->abfd = bfd_openr(filename, NULL);
	if(NULL==mAddr2line->abfd){
		status = -2;
		goto error;
	}
	
	if (! bfd_check_format_matches(mAddr2line->abfd, bfd_object, &matching)){
		status = -3;
		goto error;
	}
	
	mAddr2line->Addr2line = MAddr2line_Addr2line;
	
	return mAddr2line;
error:
	MAddr2line_Release(&mAddr2line);
	printf("MAddr2line_Init failed, status: %d\n", status);
	return NULL;
}










