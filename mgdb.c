#define _GNU_SOURCE

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

 #include <execinfo.h>

#include "bfd.h"
#include "mAddr2line.h"

int main(int argc, char* argv[])
{
	int status = 0;
	pid_t child, child_waited;
	int ifFoundLine;
	char filename[1024];
	char funcname[128];
	unsigned int line;
	
	
	if(2!=argc){
		printf("\nusauge: %s yourApp\n\n", argv[0]);
		return -1;
	}
	
	child = fork();
	if(0>child){
		printf("fork failed\n");
		return -1;
	}
	if(0==child){
		ptrace(PTRACE_TRACEME,0,NULL,NULL); 
		execl(argv[1], argv[1], NULL);
	}else{
		wait(&status);
		// printf("status: %d\n", WIFSIGNALED(status));
		
		printf("   +-----------------+\n");
		printf("   |\033[30;47mlccDebug start...\033[0m|\n");
		printf("   +-----------------+\n");
		long ptraceOption = PTRACE_O_TRACECLONE;
		ptrace(PTRACE_SETOPTIONS, child, NULL, ptraceOption); //����ptrace����
		
		ptrace(PTRACE_CONT, child, NULL, NULL);
		
		
		while (1)
        {
            child_waited = waitpid(-1, &status, __WALL);//�ȴ������ź�
				// printf("sig: %d\n", WEXITSTATUS(status));
				// printf("sig: %d\n", WTERMSIG(status));
				// printf("sig: %d\n", WSTOPSIG(status));
				// printf("sig: %d\n", WIFEXITED(status));
				// printf("sig: %d\n", WIFSIGNALED(status));
				// printf("sig: %d\n", WIFSTOPPED(status));

            if(WIFSTOPPED(status)){

				int sig = WSTOPSIG(status);
				if( (SIGTRAP == sig)||(32 < sig) )
					sig = WTERMSIG(status);
				if ( (SIGTRAP != sig)&&(32>=sig) ){ 
					unsigned long long ebp=0,eip=0;
					// int i=0;
					struct user_regs_struct regs;
					
					if(SIGSEGV == WSTOPSIG(status))
						printf("\n\033[31m %ld recieved SIGSEGV...\n \033[0m", (long)child_waited);
					else
						printf("\n\033[36m %ld recieved signal: %d\n \033[0m", (long)child_waited, sig);
					ptrace(PTRACE_GETREGS, child_waited,NULL,&regs);
					ebp = regs.rbp;
					eip = regs.rip;

					MADDR2LINE *a2l = MAddr2line_Init(argv[1]);
					if(!a2l)
						return 6;
					
					printf("\033[32m trying to locate error code line...\n\n \033[0m");
					while(1){
						ifFoundLine = a2l->Addr2line(a2l, (void*)eip, filename, funcname, &line);
						if(ifFoundLine)
							printf("%s  function: %s  (line: %d)\n", filename, funcname, line);
						else
							printf("unable to locate symbol, address %p\n", (void*)eip);

						// i++;
						// printf("%d: eip:%llx ebp:%llx\n",i,eip,ebp);
						#if __WORDSIZE == 64
							#define OFFSET 8
						#else
							#define OFFSET 4
						#endif
						eip = ptrace(PTRACE_PEEKDATA,child,ebp+OFFSET,NULL); //����֡�Ľṹ��eip�ĵ�ַ��ebp��ַ��4��������������ɺ�����������ı���ȫ�����ˡ�
						ebp = ptrace(PTRACE_PEEKDATA,child,ebp,NULL); //ע��ǰ�����е�˳���������ʹebpָ���ջ�е���һ��֡
						// printf("eip: %p, ebp: %p\n", (void*)eip, (void*)ebp);
						if( (0xffffffffffffffff == ebp) || (0 == ebp)){
							if(SIGSEGV == sig)
								child_waited = -1;
							break;
						}
						// sleep(1);
					}
					printf("\n");
					MAddr2line_Release(&a2l);
				}
            }
			/*		// �ݲ�ʵ��
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP){
                //��һ���̴߳�����һ���̷߳���ʱ���յ����ź�
                pid_t new_pid;
                if (((status >> 16) & 0xffff) == PTRACE_EVENT_CLONE){
                    if (ptrace(PTRACE_GETEVENTMSG, child_waited, 0, &new_pid) != -1)
                        printf("thread %d created\n", new_pid);
                }
            }
			*/

            if (-1 == child_waited)
                break;

            if (WIFEXITED(status)){ //�߳̽���ʱ���յ����ź�
				printf("exit normally\n");
                break;
            }

            ptrace(PTRACE_CONT, child_waited, 1, NULL);
        }

    
		
		
		
		

	#if 0
			ptrace(PTRACE_ATTACH,child,NULL,NULL);
			count++;
			ptrace(PTRACE_CONT,child,NULL,NULL);	// PTRACE_CONT //PTRACE_SINGLESTEP
			
			wait4(-1, &val, WUNTRACED, NULL);	//options���̵ȴ�ѡ���ΪWNOHANG��ʾ�������أ�����WUNTRACED��ʾ���ӽ���״̬�����仯��ŷ���
			// wait(&val);
			printf("----\n");
			if (WSTOPSIG(val) != SIGTRAP){ //ע��SIGSEGC�źž���ͨ�����ﴦ��ġ�
				printf("sig: %d\n", WEXITSTATUS(val));
				printf("sig: %d\n", WTERMSIG(val));
				printf("sig: %d\n", WSTOPSIG(val));
				printf("sig: %d\n", WIFEXITED(val));
				printf("sig: %d\n", WIFSIGNALED(val));
				printf("sig: %d\n", WIFSTOPPED(val));
				
				unsigned long long ebp=0,eip=0;
				int i=0;
				struct user_regs_struct regs;

				ptrace(PTRACE_GETREGS, child,NULL,&regs);
				printf("EIP: %llx ----EBP:%llx\n",regs.rip,regs.rbp);
				
				ebp = regs.rbp;
				eip = regs.rip;
				
				
				MADDR2LINE *a2l = MAddr2line_Init(argv[1]);
				if(!a2l)
					return 11;
				

				
				char filename[1024];
				char funcname[128];
				unsigned int line;
				int ifFound;
				
				for(;;)
				{
					
					ifFound = a2l->Addr2line(a2l, (void*)eip, filename, funcname, &line);
					printf("%s  %s  (line: %d)\n", filename, funcname, line);
					
					
					
					i++;
					printf("%d: eip:%llx ebp:%llx\n",i,eip,ebp);
					eip = ptrace(PTRACE_PEEKDATA,child,ebp+8,NULL); //����֡�Ľṹ��eip�ĵ�ַ��ebp��ַ��4��������������ɺ�����������ı���ȫ�����ˡ�
					ebp = ptrace(PTRACE_PEEKDATA,child,ebp,NULL); //ע��ǰ�����е�˳���������ʹebpָ���ջ�е���һ��֡
					if( 0xffffffffffffffff == ebp)
						break;
					sleep(1);
					
					// extern int dladdr (const void *__address, Dl_info *__info);
					// dladdr((void*)eip, &dlinfo);	//ʹ��dladdr()����ʱ�������-rdynamic����ѡ���-ldl����ѡ�
					// printf("fname: %s\n", dlinfo.dli_fname);
					// printf("sname: %s\n", dlinfo.dli_sname);
					// printf("sname: %p\n", dlinfo.dli_saddr);
					
				}
				MAddr2line_Release(&a2l);


			}
			
	#endif		
			
		kill(child, 9);
	}
	
// # define WEXITSTATUS(status)    __WEXITSTATUS (__WAIT_INT (status))
// # define WTERMSIG(status)       __WTERMSIG (__WAIT_INT (status))
// # define WSTOPSIG(status)       __WSTOPSIG (__WAIT_INT (status))
// # define WIFEXITED(status)      __WIFEXITED (__WAIT_INT (status))
// # define WIFSIGNALED(status)    __WIFSIGNALED (__WAIT_INT (status))
// # define WIFSTOPPED(status)     __WIFSTOPPED (__WAIT_INT (status))
	
	// )��PTRACE_ATTACH����PTRACE_TRACEME �������̼�ĸ��ٹ�ϵ��
// )PTRACE_PEEKTEXT, PTRACE_PEEKDATA, PTRACE_PEEKUSR�ȶ�ȡ�ӽ����ڴ�/�Ĵ����б�����ֵ��
// )PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_POKEUSR�Ȱ�ֵд�뵽�����ٽ��̵��ڴ�/�Ĵ����С�
// )��PTRACE_CONT��PTRACE_SYSCALL, PTRACE_SINGLESTEP���Ʊ����ٽ����Ժ��ַ�ʽ�������С�
// )PTRACE_DETACH, PTRACE_KILL ������̼�ĸ��ٹ�ϵ��
	
	
	
	return 0;
}


// gcc -o test1 test1.o -lbfd -liberty

/*
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <execinfo.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

	
					void *array[10];
				int size;
				char **strings;
				
				printf("\nget %d funcs: ---\n", size);
				
				size = backtrace(array, 10);
				strings = backtrace_symbols(array, size);
				
				for(i=0; i<size; i++){
					printf("%s\n", strings[i]);
				}
				free(strings);
*/