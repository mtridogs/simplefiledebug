#include <Windows.h>
#include <WinBase.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "E:\tool\mytool\bin\libdasm-1.5\libdasm.h"
#include "tlhelp32.h"
#include <Userenv.h>
#include "debugthread.h"
#pragma comment(lib, "Userenv.lib")
static DWORD WINAPI debug_A(LPVOID lpParam);

	void debugthread::SET_PROCESS_INFORMATION(PROCESS_INFORMATION pis,STARTUPINFO si,int start_time,int wait_time)
	{
		pars.pi=pis;
		pars.si=si;
		pars.start_time=start_time;
		pars.wait_time=wait_time;
	}
	bool debugthread::startdebug()
	{
	printf("[*]创建调试器线程，开始调试软件！\n");
	HANDLE hand = CreateThread(0, 0, debug_A, &pars, 0,NULL); 
	WaitForSingleObject(hand,INFINITE);
	return true;
	}
	bool debugthread::stopdebug()
	{
	DebugActiveProcessStop(pars.pi.dwProcessId);
	return true;
	}

    static DWORD WINAPI debug_A(LPVOID lpParam)
    {
	 para *a = (para *)lpParam;
	CONTEXT thread_context;
	bool key_execption;
	DEBUG_EVENT debugevent;
	FILE *ERRORfile=fopen("ERROELOG.TXT", "a+");
	HANDLE openthread;
	HANDLE openprocess;
	int exception_key=0;
	INSTRUCTION inst;
	char *memery_context = (char*)malloc(sizeof(char));
	char *memory_context = (char*)malloc(sizeof(char));

//**************************************************************************************************************************************

	bool debug_creat_init = DebugActiveProcess(a->pi.dwProcessId);
	if(!debug_creat_init)
	{
	printf("[*]调试器附加失败！错误代码：%d 请检查系统状况！\n",GetLastError());
	fprintf(ERRORfile, "调试器附加失败，请检查系统状况！\n");
	getchar();
	fprintf(ERRORfile,"====================================================================================================调试结束\n");
	return 0;
	}
	printf("[!]调试器附加成功！开始进行调试循环\n");
	while(GetTickCount()-a->start_time<=a->wait_time)
	{
		if(WaitForDebugEvent(&debugevent,1000))//INFINITE一直等待调试事件的发生
		{
			if(debugevent.dwDebugEventCode!=EXCEPTION_DEBUG_EVENT)//不是调试异常事件
			{
				ContinueDebugEvent(debugevent.dwProcessId,debugevent.dwThreadId,DBG_CONTINUE);//释放所有的线程
				continue;
			}
			if((openthread =OpenThread(THREAD_ALL_ACCESS,FALSE,debugevent.dwThreadId))==NULL)
			{
				printf("附加进程出错，错误代码：%d",GetLastError());
				fprintf(ERRORfile, "附加进程出错，错误代码：%d",GetLastError());
				getchar();
				fprintf(ERRORfile,"====================================================================================================调试结束\n");
				return 0;
			}
			thread_context.ContextFlags=CONTEXT_FULL;
			if(GetThreadContext(openthread,&thread_context)==0)
			{
			printf("获取进程信息失败！ 错误代码：%d\n",GetLastError());
			fprintf(ERRORfile, "获取进程信息失败！\n");
			getchar();
			fprintf(ERRORfile,"====================================================================================================调试结束\n");
			return 0;
			}
			switch (debugevent.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case CREATE_THREAD_DEBUG_EVENT:
				printf("[*]调试开始,调试事件CREATE_THREAD_DEBUG_EVENT\n");
				break;
			case EXCEPTION_ACCESS_VIOLATION:
					key_execption=true;
					printf("[!]软件错误！非法访问（EXCEPTION_ACCESS_VIOLATION）！\n");
					fprintf(ERRORfile, "[*]软件错误！非法访问（EXCEPTION_ACCESS_VIOLATION）！\n");
					break;
			case EXCEPTION_INT_DIVIDE_BY_ZERO:
				key_execption=true;
				printf("[!]软件错误！原因EXCEPTION_INT_DIVIDE_BY_ZERO");
				fprintf(ERRORfile, "[*]软件错误！原因EXCEPTION_INT_DIVIDE_BY_ZERO");
				break;
			case EXCEPTION_STACK_OVERFLOW:
				key_execption=true;
				printf("[!]软件错误！原因EXCEPTION_STACK_OVERFLOW");
				fprintf(ERRORfile, "[*]软件错误！原因EXCEPTION_STACK_OVERFLOW");
			case EXIT_PROCESS_DEBUG_EVENT:
				printf("[!]软件退出调试器！\n");
				break;
			default:
				key_execption=FALSE;
				ContinueDebugEvent(debugevent.dwProcessId,debugevent.dwThreadId,DBG_CONTINUE);
			}

			if(key_execption)//异常逆向
			{
				exception_key++;
				if((openprocess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,debugevent.dwProcessId))==NULL)
				{
				printf("[!]错误！进程附加失败！\n");
				fprintf(ERRORfile, "[!]错误！进程附加失败！\n");
				return -1;
				}

				ReadProcessMemory(openprocess,(void*)thread_context.Eip,memery_context,32,NULL);
				printf("*******************************************************************************\n");
				get_instruction(&inst,(BYTE *)memery_context,MODE_32);
				get_instruction_string(&inst,FORMAT_INTEL,0,memory_context,64);
				printf("[*]发现异常\n CPU:  EIP [%x] EAX [%x] EBX [%x] ECX [%x] EDX [%x]\n ",thread_context.Eip,thread_context.Eax,thread_context.Ebx,thread_context.Ecx,thread_context.Edx);
				printf("[*]ESI [%x] EDI [%x] EBP [%x]\n",thread_context.Esi,thread_context.Edi,thread_context.Ebp);
				printf("[*]异常内存 %x",memery_context);

				fprintf(ERRORfile,"[*]发现异常\n CPU:  EIP [%x] EAX [%x] EBX [%x] ECX [%x] EDX [%x]\n ",thread_context.Eip,thread_context.Eax,thread_context.Ebx,thread_context.Ecx,thread_context.Edx);
				fprintf(ERRORfile,"[*]ESI [%x] EDI [%x] EBP [%x]\n",thread_context.Esi,thread_context.Edi,thread_context.Ebp);
				fprintf(ERRORfile,"[*]异常内存 %x",memery_context);
				key_execption=FALSE;
				printf("[*]异常分析完成！\n");
				printf("*******************************************************************************\n");
			}
			ContinueDebugEvent(debugevent.dwProcessId,debugevent.dwThreadId,DBG_CONTINUE);
			printf("剩余调试时间:  %d",GetTickCount()-a->start_time);
		}
	}
	printf("[*]进程  调试完成，花费时间：%dms，发现异常数目为：%d\n",a->wait_time,exception_key);
	printf("[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]\n");
	fprintf(ERRORfile,"[*]进程  调试完成，花费时间：%dms，发现异常数目为：%d\n",a->wait_time,exception_key);
	fprintf(ERRORfile,"[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]\n");
        return 0;
   }


