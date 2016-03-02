#include <Windows.h>
#include <WinBase.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "E:\tool\mytool\bin\libdasm-1.5\libdasm.h"
#include "tlhelp32.h"
#include <Userenv.h>
#pragma comment(lib, "Userenv.lib")


struct para
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	int start_time;
	int wait_time;
};

class debugthread{
private:
     para pars;
public:
	void SET_PROCESS_INFORMATION(PROCESS_INFORMATION pis,STARTUPINFO si,int start_time,int wait_time);
	bool startdebug();
	bool stopdebug();
    //static DWORD WINAPI debug_A(LPVOID lpParam);
};