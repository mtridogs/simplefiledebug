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
	printf("[*]�����������̣߳���ʼ���������\n");
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
	printf("[*]����������ʧ�ܣ�������룺%d ����ϵͳ״����\n",GetLastError());
	fprintf(ERRORfile, "����������ʧ�ܣ�����ϵͳ״����\n");
	getchar();
	fprintf(ERRORfile,"====================================================================================================���Խ���\n");
	return 0;
	}
	printf("[!]���������ӳɹ�����ʼ���е���ѭ��\n");
	while(GetTickCount()-a->start_time<=a->wait_time)
	{
		if(WaitForDebugEvent(&debugevent,1000))//INFINITEһֱ�ȴ������¼��ķ���
		{
			if(debugevent.dwDebugEventCode!=EXCEPTION_DEBUG_EVENT)//���ǵ����쳣�¼�
			{
				ContinueDebugEvent(debugevent.dwProcessId,debugevent.dwThreadId,DBG_CONTINUE);//�ͷ����е��߳�
				continue;
			}
			if((openthread =OpenThread(THREAD_ALL_ACCESS,FALSE,debugevent.dwThreadId))==NULL)
			{
				printf("���ӽ��̳���������룺%d",GetLastError());
				fprintf(ERRORfile, "���ӽ��̳���������룺%d",GetLastError());
				getchar();
				fprintf(ERRORfile,"====================================================================================================���Խ���\n");
				return 0;
			}
			thread_context.ContextFlags=CONTEXT_FULL;
			if(GetThreadContext(openthread,&thread_context)==0)
			{
			printf("��ȡ������Ϣʧ�ܣ� ������룺%d\n",GetLastError());
			fprintf(ERRORfile, "��ȡ������Ϣʧ�ܣ�\n");
			getchar();
			fprintf(ERRORfile,"====================================================================================================���Խ���\n");
			return 0;
			}
			switch (debugevent.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case CREATE_THREAD_DEBUG_EVENT:
				printf("[*]���Կ�ʼ,�����¼�CREATE_THREAD_DEBUG_EVENT\n");
				break;
			case EXCEPTION_ACCESS_VIOLATION:
					key_execption=true;
					printf("[!]������󣡷Ƿ����ʣ�EXCEPTION_ACCESS_VIOLATION����\n");
					fprintf(ERRORfile, "[*]������󣡷Ƿ����ʣ�EXCEPTION_ACCESS_VIOLATION����\n");
					break;
			case EXCEPTION_INT_DIVIDE_BY_ZERO:
				key_execption=true;
				printf("[!]�������ԭ��EXCEPTION_INT_DIVIDE_BY_ZERO");
				fprintf(ERRORfile, "[*]�������ԭ��EXCEPTION_INT_DIVIDE_BY_ZERO");
				break;
			case EXCEPTION_STACK_OVERFLOW:
				key_execption=true;
				printf("[!]�������ԭ��EXCEPTION_STACK_OVERFLOW");
				fprintf(ERRORfile, "[*]�������ԭ��EXCEPTION_STACK_OVERFLOW");
			case EXIT_PROCESS_DEBUG_EVENT:
				printf("[!]����˳���������\n");
				break;
			default:
				key_execption=FALSE;
				ContinueDebugEvent(debugevent.dwProcessId,debugevent.dwThreadId,DBG_CONTINUE);
			}

			if(key_execption)//�쳣����
			{
				exception_key++;
				if((openprocess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,debugevent.dwProcessId))==NULL)
				{
				printf("[!]���󣡽��̸���ʧ�ܣ�\n");
				fprintf(ERRORfile, "[!]���󣡽��̸���ʧ�ܣ�\n");
				return -1;
				}

				ReadProcessMemory(openprocess,(void*)thread_context.Eip,memery_context,32,NULL);
				printf("*******************************************************************************\n");
				get_instruction(&inst,(BYTE *)memery_context,MODE_32);
				get_instruction_string(&inst,FORMAT_INTEL,0,memory_context,64);
				printf("[*]�����쳣\n CPU:  EIP [%x] EAX [%x] EBX [%x] ECX [%x] EDX [%x]\n ",thread_context.Eip,thread_context.Eax,thread_context.Ebx,thread_context.Ecx,thread_context.Edx);
				printf("[*]ESI [%x] EDI [%x] EBP [%x]\n",thread_context.Esi,thread_context.Edi,thread_context.Ebp);
				printf("[*]�쳣�ڴ� %x",memery_context);

				fprintf(ERRORfile,"[*]�����쳣\n CPU:  EIP [%x] EAX [%x] EBX [%x] ECX [%x] EDX [%x]\n ",thread_context.Eip,thread_context.Eax,thread_context.Ebx,thread_context.Ecx,thread_context.Edx);
				fprintf(ERRORfile,"[*]ESI [%x] EDI [%x] EBP [%x]\n",thread_context.Esi,thread_context.Edi,thread_context.Ebp);
				fprintf(ERRORfile,"[*]�쳣�ڴ� %x",memery_context);
				key_execption=FALSE;
				printf("[*]�쳣������ɣ�\n");
				printf("*******************************************************************************\n");
			}
			ContinueDebugEvent(debugevent.dwProcessId,debugevent.dwThreadId,DBG_CONTINUE);
			printf("ʣ�����ʱ��:  %d",GetTickCount()-a->start_time);
		}
	}
	printf("[*]����  ������ɣ�����ʱ�䣺%dms�������쳣��ĿΪ��%d\n",a->wait_time,exception_key);
	printf("[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]\n");
	fprintf(ERRORfile,"[*]����  ������ɣ�����ʱ�䣺%dms�������쳣��ĿΪ��%d\n",a->wait_time,exception_key);
	fprintf(ERRORfile,"[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]\n");
        return 0;
   }


