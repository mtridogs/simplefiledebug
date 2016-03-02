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
	//	printf("请输入参数！\n");
	//	getchar();
	//	return 0;
	//}
	argv[1]="1000";
	argv[2]="E:\\tool\\pangolin\\professinal_edition\\pangolin.exe";
	//argv[2]="E:\\Media\\cc.exe";
//=============================================================
	int wait_time = atoi(argv[1]);//参数1，调试等待时间
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
//=============================================================UI进程初始化变量
	HANDLE hToken;//桌面令牌
	HANDLE hnewToken;//令牌for create process
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
	printf("[!]获取系统权限令牌失败！错误代码：%d 请检查系统状况！\n",GetLastError());
	getchar();
	return 0;
	}

	bRet = DuplicateTokenEx(hToken, 0, NULL, SecurityImpersonation,TokenPrimary, &hnewToken);
	if(!bRet){
	printf("[!]系统令牌传递失败！错误代码：%d 请检查系统状况！\n",GetLastError());
	getchar();
	return 0;
	}

	bRet = AllocateAndInitializeSid(&MLAuthority,1,SECURITY_MANDATORY_MEDIUM_RID,0,0,0,0,0,0,0,&pIntegritySid);
	if(!bRet){
	printf("[!]系统提权失败！错误代码：%d 请检查系统状况！\n",GetLastError());
	getchar();
	return 0;
	}

	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	tml.Label.Sid = pIntegritySid;

	bRet = SetTokenInformation(hnewToken,TokenIntegrityLevel, &tml, (sizeof(tml) + GetLengthSid(pIntegritySid)));
	if(!bRet){
	printf("[!]系统权限令牌设置失败！错误代码：%d 请检查系统状况！\n",GetLastError());
	getchar();
	return 0;
	}
	bRet = CreateEnvironmentBlock(&pEnvironment,hnewToken, FALSE);
	if(!bRet){
	printf("[!]环境变量模块设置失败！错误代码：%d 请检查系统状况！\n",GetLastError());
	getchar();
	return 0;
	}
	//==========================================================UI添加代码
	fprintf(ERRORfile,"[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]\n");
	fprintf(ERRORfile,"[！]进程%s调试开始，预计等待时间%d\n",argv[0],wait_time);
	printf("[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]\n");
	printf("[！]进程%s调试开始，预计等待时间%d\n",argv[0],wait_time);
	if(wait_time<=0)
	{
		printf("时间参数不正确！\n");
		fprintf(ERRORfile, "错误，时间参数不正确！\n");
		getchar();
		fprintf(ERRORfile,"====================================================================================================调试结束\n");
		return 0;
	}

	strcpy(command_line_T,argv[2]);
	
	//process_ret = CreateProcess(NULL,command_line_T,NULL,NULL,FALSE,DEBUG_PROCESS,NULL,NULL,&si,&pi);
	
	process_ret = CreateProcessAsUser(hnewToken,TEXT(command_line_T),NULL,NULL,NULL,FALSE,dwCreationFlag,pEnvironment,NULL,&si,&pi);
	if(!process_ret)
	{
	printf("[*]进程创建失败！错误代码：%d 请手动检查路径或其他错误！\n",GetLastError());
	printf("系统显示的错误路径为：%s\n",command_line_T);
	fprintf(ERRORfile, "[*]进程创建失败！错误代码：%d 请手动检查路径或其他错误！\n",GetLastError());
	getchar();
	fprintf(ERRORfile,"====================================================================================================调试结束\n");
	return 0;
	}
	
	debug_thread.SET_PROCESS_INFORMATION(pi,si,start_time,wait_time);
	debug_thread.startdebug();

	getchar();
	//*************************************************************************************************************************************
	//bool debug_creat_init = DebugActiveProcess(pi.dwProcessId);
	//if(!debug_creat_init)
	//{
	//printf("[*]调试器附加失败！错误代码：%d 请检查系统状况！\n",GetLastError());
	//fprintf(ERRORfile, "调试器附加失败，请检查系统状况！\n");
	//getchar();
	//fprintf(ERRORfile,"====================================================================================================调试结束\n");
	//return 0;
	//}
	//printf("[!]调试器附加成功！开始进行调试循环\n");
	//while(GetTickCount()-start_time<=wait_time)
	//{
	//	if(WaitForDebugEvent(&debugevent,100))//INFINITE一直等待调试事件的发生
	//	{
	//		if(debugevent.dwDebugEventCode!=EXCEPTION_DEBUG_EVENT)//不是调试异常事件
	//		{
	//			ContinueDebugEvent(debugevent.dwProcessId,debugevent.dwThreadId,DBG_CONTINUE);//释放所有的线程
	//			continue;
	//		}
	//		if((openthread =OpenThread(THREAD_ALL_ACCESS,FALSE,debugevent.dwThreadId))==NULL)
	//		{
	//			printf("附加进程出错，错误代码：%d",GetLastError());
	//			fprintf(ERRORfile, "附加进程出错，错误代码：%d",GetLastError());
	//			getchar();
	//			fprintf(ERRORfile,"====================================================================================================调试结束\n");
	//			return 0;
	//		}
	//		thread_context.ContextFlags=CONTEXT_FULL;
	//		if(GetThreadContext(openthread,&thread_context)==0)
	//		{
	//		printf("获取进程信息失败！ 错误代码：%d\n",GetLastError());
	//		fprintf(ERRORfile, "获取进程信息失败！\n");
	//		getchar();
	//		fprintf(ERRORfile,"====================================================================================================调试结束\n");
	//		return 0;
	//		}
	//		switch (debugevent.u.Exception.ExceptionRecord.ExceptionCode)
	//		{
	//		case EXCEPTION_ACCESS_VIOLATION:
	//				key_execption=true;
	//				printf("软件错误！非法访问（EXCEPTION_ACCESS_VIOLATION）！\n");
	//				fprintf(ERRORfile, "[*]软件错误！非法访问（EXCEPTION_ACCESS_VIOLATION）！\n");
	//				break;
	//		case EXCEPTION_INT_DIVIDE_BY_ZERO:
	//			key_execption=true;
	//			printf("软件错误！原因EXCEPTION_INT_DIVIDE_BY_ZERO");
	//			fprintf(ERRORfile, "[*]软件错误！原因EXCEPTION_INT_DIVIDE_BY_ZERO");
	//			break;
	//		case EXCEPTION_STACK_OVERFLOW:
	//			key_execption=true;
	//			printf("软件错误！原因EXCEPTION_STACK_OVERFLOW");
	//			fprintf(ERRORfile, "[*]软件错误！原因EXCEPTION_STACK_OVERFLOW");
	//			break;
	//		default:
	//			key_execption=FALSE;
	//			ContinueDebugEvent(debugevent.dwProcessId,debugevent.dwThreadId,DBG_CONTINUE);
	//		}

	//		if(key_execption)//异常逆向
	//		{
	//			exception_key++;
	//			if((openprocess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,debugevent.dwProcessId))==NULL)
	//			{
	//			printf("错误！进程附加失败！\n");
	//			fprintf(ERRORfile, "错误！进程附加失败！\n");
	//			return -1;
	//			}

	//			ReadProcessMemory(openprocess,(void*)thread_context.Eip,memery_context,32,NULL);
	//			
	//			get_instruction(&inst,(BYTE *)memery_context,MODE_32);
	//			get_instruction_string(&inst,FORMAT_INTEL,0,memory_context,64);
	//			printf("[*]发现异常\n CPU:  EIP [%x] EAX [%x] EBX [%x] ECX [%x] EDX [%x]\n ",thread_context.Eip,thread_context.Eax,thread_context.Ebx,thread_context.Ecx,thread_context.Edx);
	//			printf("[*]ESI [%x] EDI [%x] EBP [%x]\n",thread_context.Esi,thread_context.Edi,thread_context.Ebp);
	//			printf("[*]异常内存 %s",memery_context);

	//			fprintf(ERRORfile,"[*]发现异常\n CPU:  EIP [%x] EAX [%x] EBX [%x] ECX [%x] EDX [%x]\n ",thread_context.Eip,thread_context.Eax,thread_context.Ebx,thread_context.Ecx,thread_context.Edx);
	//			fprintf(ERRORfile,"[*]ESI [%x] EDI [%x] EBP [%x]\n",thread_context.Esi,thread_context.Edi,thread_context.Ebp);
	//			fprintf(ERRORfile,"[*]异常内存 %s",memery_context);
	//		}
	//	}
	//}
	//printf("[*]进程 %s 调试完成，花费时间：%dms，发现异常数目为：%d\n",argv[0],wait_time,exception_key);
	//printf("[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]\n");
	//fprintf(ERRORfile,"[*]进程 %s 调试完成，花费时间：%dms，发现异常数目为：%d\n",argv[0],wait_time,exception_key);
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