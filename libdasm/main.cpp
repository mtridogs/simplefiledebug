#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "E:\tool\mytool\bin\libdasm-1.5\libdasm.h"
#include "tlhelp32.h"
#include <Userenv.h>
#include <windows.h>
#include "debugthread.h"
unsigned char data[] = "\x01\x02";
#pragma comment(lib, "Userenv.lib")
BOOL   GetTokenByName(HANDLE &hToken,LPSTR lpName);
int main(int argc, char* argv[])
{
	//if(argc==1)
	//{
	//	printf("�����������\n");
	//	getchar();
	//	return 0;
	//}
	argv[1]="1000";
	argv[2]="E:\\tool\\pangolin\\professinal_edition\\pangolin.exe";
	//argv[2]="E:\\Media\\cc.exe";
//=============================================================
	int wait_time = atoi(argv[1]);//����1�����Եȴ�ʱ��
	char *command_line_T = (char*)malloc(sizeof(char)*strlen(argv[2]));
	bool process_ret;
	STARTUPINFO si = {sizeof(si)};//process create
    PROCESS_INFORMATION pi;//process create
	int start_time = GetTickCount();
	DEBUG_EVENT debugevent;
	HANDLE openthread;
	HANDLE openprocess;
	CONTEXT thread_context;
	bool key_execption;
	FILE *ERRORfile=fopen("ERROELOG.TXT", "a+");
	char *memery_context = (char*)malloc(sizeof(char));
	char *memory_context = (char*)malloc(sizeof(char));
	INSTRUCTION inst;
	int exception_key=0;
	debugthread debug_thread;
//=============================================================UI���̳�ʼ������
	HANDLE hToken;//��������
	HANDLE hnewToken;//����for create process
	SECURITY_ATTRIBUTES sa;
	SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
	PSID pIntegritySid;
	TOKEN_MANDATORY_LABEL tml;
	DWORD dwCreationFlag;
	LPVOID pEnvironment;
	bool bRet;
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.lpDesktop = TEXT("winsta0\\default");
	si.wShowWindow = SW_SHOW;
	dwCreationFlag =  NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;
//=============================================================
	//if(!GetTokenByName(hToken,"EXPLORER\.EXE")){   
 //     return 0;   
 //   }

	bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY,&hToken);

	if(!bRet){
	printf("[!]��ȡϵͳȨ������ʧ�ܣ�������룺%d ����ϵͳ״����\n",GetLastError());
	getchar();
	return 0;
	}

	bRet = DuplicateTokenEx(hToken, 0, NULL, SecurityImpersonation,TokenPrimary, &hnewToken);
	if(!bRet){
	printf("[!]ϵͳ���ƴ���ʧ�ܣ�������룺%d ����ϵͳ״����\n",GetLastError());
	getchar();
	return 0;
	}

	bRet = AllocateAndInitializeSid(&MLAuthority,1,SECURITY_MANDATORY_MEDIUM_RID,0,0,0,0,0,0,0,&pIntegritySid);
	if(!bRet){
	printf("[!]ϵͳ��Ȩʧ�ܣ�������룺%d ����ϵͳ״����\n",GetLastError());
	getchar();
	return 0;
	}

	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	tml.Label.Sid = pIntegritySid;

	bRet = SetTokenInformation(hnewToken,TokenIntegrityLevel, &tml, (sizeof(tml) + GetLengthSid(pIntegritySid)));
	if(!bRet){
	printf("[!]ϵͳȨ����������ʧ�ܣ�������룺%d ����ϵͳ״����\n",GetLastError());
	getchar();
	return 0;
	}
	bRet = CreateEnvironmentBlock(&pEnvironment,hnewToken, FALSE);
	if(!bRet){
	printf("[!]��������ģ������ʧ�ܣ�������룺%d ����ϵͳ״����\n",GetLastError());
	getchar();
	return 0;
	}
	//==========================================================UI��Ӵ���
	fprintf(ERRORfile,"[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]\n");
	fprintf(ERRORfile,"[��]����%s���Կ�ʼ��Ԥ�Ƶȴ�ʱ��%d\n",argv[0],wait_time);
	printf("[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]\n");
	printf("[��]����%s���Կ�ʼ��Ԥ�Ƶȴ�ʱ��%d\n",argv[0],wait_time);
	if(wait_time<=0)
	{
		printf("ʱ���������ȷ��\n");
		fprintf(ERRORfile, "����ʱ���������ȷ��\n");
		getchar();
		fprintf(ERRORfile,"====================================================================================================���Խ���\n");
		return 0;
	}

	strcpy(command_line_T,argv[2]);
	
	//process_ret = CreateProcess(NULL,command_line_T,NULL,NULL,FALSE,DEBUG_PROCESS,NULL,NULL,&si,&pi);
	
	process_ret = CreateProcessAsUser(hnewToken,TEXT(command_line_T),NULL,NULL,NULL,FALSE,dwCreationFlag,pEnvironment,NULL,&si,&pi);
	if(!process_ret)
	{
	printf("[*]���̴���ʧ�ܣ�������룺%d ���ֶ����·������������\n",GetLastError());
	printf("ϵͳ��ʾ�Ĵ���·��Ϊ��%s\n",command_line_T);
	fprintf(ERRORfile, "[*]���̴���ʧ�ܣ�������룺%d ���ֶ����·������������\n",GetLastError());
	getchar();
	fprintf(ERRORfile,"====================================================================================================���Խ���\n");
	return 0;
	}
	
	debug_thread.SET_PROCESS_INFORMATION(pi,si,start_time,wait_time);
	debug_thread.startdebug();

	getchar();
	//*************************************************************************************************************************************
	//bool debug_creat_init = DebugActiveProcess(pi.dwProcessId);
	//if(!debug_creat_init)
	//{
	//printf("[*]����������ʧ�ܣ�������룺%d ����ϵͳ״����\n",GetLastError());
	//fprintf(ERRORfile, "����������ʧ�ܣ�����ϵͳ״����\n");
	//getchar();
	//fprintf(ERRORfile,"====================================================================================================���Խ���\n");
	//return 0;
	//}
	//printf("[!]���������ӳɹ�����ʼ���е���ѭ��\n");
	//while(GetTickCount()-start_time<=wait_time)
	//{
	//	if(WaitForDebugEvent(&debugevent,100))//INFINITEһֱ�ȴ������¼��ķ���
	//	{
	//		if(debugevent.dwDebugEventCode!=EXCEPTION_DEBUG_EVENT)//���ǵ����쳣�¼�
	//		{
	//			ContinueDebugEvent(debugevent.dwProcessId,debugevent.dwThreadId,DBG_CONTINUE);//�ͷ����е��߳�
	//			continue;
	//		}
	//		if((openthread =OpenThread(THREAD_ALL_ACCESS,FALSE,debugevent.dwThreadId))==NULL)
	//		{
	//			printf("���ӽ��̳���������룺%d",GetLastError());
	//			fprintf(ERRORfile, "���ӽ��̳���������룺%d",GetLastError());
	//			getchar();
	//			fprintf(ERRORfile,"====================================================================================================���Խ���\n");
	//			return 0;
	//		}
	//		thread_context.ContextFlags=CONTEXT_FULL;
	//		if(GetThreadContext(openthread,&thread_context)==0)
	//		{
	//		printf("��ȡ������Ϣʧ�ܣ� ������룺%d\n",GetLastError());
	//		fprintf(ERRORfile, "��ȡ������Ϣʧ�ܣ�\n");
	//		getchar();
	//		fprintf(ERRORfile,"====================================================================================================���Խ���\n");
	//		return 0;
	//		}
	//		switch (debugevent.u.Exception.ExceptionRecord.ExceptionCode)
	//		{
	//		case EXCEPTION_ACCESS_VIOLATION:
	//				key_execption=true;
	//				printf("������󣡷Ƿ����ʣ�EXCEPTION_ACCESS_VIOLATION����\n");
	//				fprintf(ERRORfile, "[*]������󣡷Ƿ����ʣ�EXCEPTION_ACCESS_VIOLATION����\n");
	//				break;
	//		case EXCEPTION_INT_DIVIDE_BY_ZERO:
	//			key_execption=true;
	//			printf("�������ԭ��EXCEPTION_INT_DIVIDE_BY_ZERO");
	//			fprintf(ERRORfile, "[*]�������ԭ��EXCEPTION_INT_DIVIDE_BY_ZERO");
	//			break;
	//		case EXCEPTION_STACK_OVERFLOW:
	//			key_execption=true;
	//			printf("�������ԭ��EXCEPTION_STACK_OVERFLOW");
	//			fprintf(ERRORfile, "[*]�������ԭ��EXCEPTION_STACK_OVERFLOW");
	//			break;
	//		default:
	//			key_execption=FALSE;
	//			ContinueDebugEvent(debugevent.dwProcessId,debugevent.dwThreadId,DBG_CONTINUE);
	//		}

	//		if(key_execption)//�쳣����
	//		{
	//			exception_key++;
	//			if((openprocess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,debugevent.dwProcessId))==NULL)
	//			{
	//			printf("���󣡽��̸���ʧ�ܣ�\n");
	//			fprintf(ERRORfile, "���󣡽��̸���ʧ�ܣ�\n");
	//			return -1;
	//			}

	//			ReadProcessMemory(openprocess,(void*)thread_context.Eip,memery_context,32,NULL);
	//			
	//			get_instruction(&inst,(BYTE *)memery_context,MODE_32);
	//			get_instruction_string(&inst,FORMAT_INTEL,0,memory_context,64);
	//			printf("[*]�����쳣\n CPU:  EIP [%x] EAX [%x] EBX [%x] ECX [%x] EDX [%x]\n ",thread_context.Eip,thread_context.Eax,thread_context.Ebx,thread_context.Ecx,thread_context.Edx);
	//			printf("[*]ESI [%x] EDI [%x] EBP [%x]\n",thread_context.Esi,thread_context.Edi,thread_context.Ebp);
	//			printf("[*]�쳣�ڴ� %s",memery_context);

	//			fprintf(ERRORfile,"[*]�����쳣\n CPU:  EIP [%x] EAX [%x] EBX [%x] ECX [%x] EDX [%x]\n ",thread_context.Eip,thread_context.Eax,thread_context.Ebx,thread_context.Ecx,thread_context.Edx);
	//			fprintf(ERRORfile,"[*]ESI [%x] EDI [%x] EBP [%x]\n",thread_context.Esi,thread_context.Edi,thread_context.Ebp);
	//			fprintf(ERRORfile,"[*]�쳣�ڴ� %s",memery_context);
	//		}
	//	}
	//}
	//printf("[*]���� %s ������ɣ�����ʱ�䣺%dms�������쳣��ĿΪ��%d\n",argv[0],wait_time,exception_key);
	//printf("[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]\n");
	//fprintf(ERRORfile,"[*]���� %s ������ɣ�����ʱ�䣺%dms�������쳣��ĿΪ��%d\n",argv[0],wait_time,exception_key);
	//fprintf(ERRORfile,"[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]\n");

	return 0;

}


BOOL   GetTokenByName(HANDLE &hToken,LPSTR lpName)   
  {   
    if(!lpName) {   
      return   FALSE; }   
		HANDLE hProcessSnap=NULL;     
		BOOL bRet=FALSE;     
		PROCESSENTRY32 pe32={0};
		hProcessSnap   =   CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);     
		if(hProcessSnap==INVALID_HANDLE_VALUE)     
			return (FALSE);
		pe32.dwSize = sizeof(PROCESSENTRY32);     
		if(Process32First(hProcessSnap,&pe32)){       
		do{   
        if(!strcmp(_strupr(pe32.szExeFile),_strupr(lpName))){   
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION,   
		FALSE,pe32.th32ProcessID);   
		bRet = OpenProcessToken(hProcess,TOKEN_ALL_ACCESS,&hToken);   
		CloseHandle(hProcessSnap);     
		return (bRet);}}     
		while(Process32Next(hProcessSnap,   &pe32));     
				bRet = TRUE;}     
		else     
				bRet = FALSE;   
		CloseHandle(hProcessSnap);     
		return (bRet);   
  }   