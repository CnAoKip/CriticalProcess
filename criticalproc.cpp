
#include <windows.h>
#include <Tlhelp32.h>
#include <stdio.h>
#include <locale.h>
#define ProcessBreakOnTermination 29

typedef NTSTATUS(NTAPI *_NtSetInformationProcess)(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
typedef NTSTATUS(NTAPI *_NtQueryInformationProcess)(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength OPTIONAL);

BOOL WINAPI EnableDebugPrivilege(BOOL fEnable)
{
	BOOL fOk = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}

BOOL CallNtSetInformationProcess(HANDLE hProcess, ULONG Flag)
{
	_NtSetInformationProcess NtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtSetInformationProcess");
	if (!NtSetInformationProcess)
	{
		return 0;
	}
	if(NtSetInformationProcess(hProcess, (PROCESS_INFORMATION_CLASS)ProcessBreakOnTermination, &Flag, sizeof(ULONG))<0)
		return 0;
	return 1;
}

BOOL CallNtQueryInformationProcess(HANDLE hProcess, PULONG pFlag){
	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQueryInformationProcess");
	if (!NtQueryInformationProcess)
	{
		return 0;
	}
	if(NtQueryInformationProcess(hProcess, (PROCESS_INFORMATION_CLASS)ProcessBreakOnTermination, pFlag, sizeof(ULONG), NULL)<0)
		return 0;
	return 1;
}

DWORD WINAPI GetProcessID(LPCSTR FileName)
{
	HANDLE myhProcess;
	PROCESSENTRY32 mype;
	mype.dwSize = sizeof(PROCESSENTRY32); 
	BOOL mybRet;
	myhProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	mybRet = Process32First(myhProcess,&mype);
	while(mybRet){
		if(lstrcmpA(FileName ,mype.szExeFile) == 0) return mype.th32ProcessID;
		else mybRet = Process32Next(myhProcess,&mype);
	}
	return 0;
}

static void print_help(){
	fwprintf(stderr, L"用法：CriticalProc.exe [/n imagename] [/p [pid]] [/t] [/f] [/q]\n\n\
描述：\n\
	使用此工具修改或判断任意进程的关键度。\n\n\
参数：\n\
	/n imagename      通过imagename 指定要设定关键度的进程。\n\
	/p [pid]          通过pid 指定要设定关键度的进程。\n\
	/t                设为关键进程。\n\
	/f                设为普通进程。\n\
	/q                判断指定的进程的关键度。\n");
	
	exit(0);
}

static void print_err(LPCWSTR lpWhere, DWORD dwLastError, LPCWSTR lpExtraInfo){
	LPWSTR lpBuffer = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, 1024 * 2);
	LPVOID lpMsgBuf;

    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                  FORMAT_MESSAGE_FROM_SYSTEM | 
                  FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, GetLastError(),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
            (LPWSTR) &lpMsgBuf, 0, NULL
    );
	
	wprintf(L"%s失败！原因：%s\n", lpWhere, (LPCWSTR)lpMsgBuf);
	if(!lpExtraInfo) wprintf(L"%s\n", lpExtraInfo);
	exit(1);
} 

HRESULT ParseCommandLine(int argc, char* argv[], DWORD *pPid, PBOOL pfFlag, PBOOL pfQuery){
	BOOL PidSet  =  FALSE;
	BOOL FlagSet =  FALSE;
	for (int index = 1; index < argc; index++)
    {
        if (argv[index][0] == L'-' || argv[index][0] == L'/')
        {
            switch (towlower(argv[index][1]))
            {
                case L'?': /* Help */
                    print_help();
                    return ERROR_SUCCESS;

                case L'n': 
                	if(PidSet){
                		wprintf(L"查找指定进程失败。可能是您指定了多个进程。请核对您的输入。\n");
                		exit(1);
					}
                    if (index+1 >= argc)
                        return ERROR_INVALID_DATA;
                    if (!argv[index+1] || lstrlenA(argv[index+1]) <= 512)
                    {
                        *pPid = GetProcessID(argv[index+1]);
                        PidSet = TRUE;
                        if(*pPid == 0){
                        	print_err(L"查找指定进程", ERROR_INVALID_DATA, L"请核对您的输入。");
                        	exit(1);
						}
                        index++;
                    }
                    else
                    {
                        print_err(L"查找指定进程", ERROR_BAD_LENGTH, L"请将进程名控制在1~512个字符之间。");
                        return ERROR_BAD_LENGTH;
                    }
                    break;

                case L'p': 
                	if(PidSet){
                		wprintf(L"查找指定进程失败。可能是您指定了多个进程。请核对您的输入。\n");
                		exit(1);
					}
                    if (index+1 >= argc)
                        return ERROR_INVALID_DATA;
                    *pPid = atoi(argv[index+1]);
                    PidSet = TRUE; 
                    index++;
                    break;

                case L'f':
                	if(FlagSet){
                		wprintf(L"指定关键度失败。可能是您指定了多个关键度。请核对您的输入。\n");
                		exit(1);
					}
                	*pfFlag = FALSE;
                	FlagSet = TRUE;
                    break;

                case L't':
                	if(FlagSet){
                		wprintf(L"指定关键度失败。可能是您指定了多个关键度。请核对您的输入。\n");
                		exit(1);
					}
                    *pfFlag = TRUE;
                	FlagSet = TRUE;
                    break;

                case L'q':
                    *pfQuery = TRUE;
                    break;

                default:
                    /* Unknown arguments will exit the program. */
                    print_help();
                    return ERROR_SUCCESS;
            }
        }
    }
}

int main(int argc, char *argv[]){
	BOOL     fFlag;
	DWORD    pid;
	HANDLE   hProcess;
	BOOL     fSuccess;
	BOOL     fQuery = FALSE;
	
	setlocale(LC_ALL, "chs");
	wprintf(L"CriticalProc v1.0 by 旮沓曼_gt428\n");
	if(argc <= 1) print_help();
	else ParseCommandLine(argc, argv, &pid, &fFlag, &fQuery);
	
	
	fSuccess = EnableDebugPrivilege(TRUE);
	if(!fSuccess) print_err(L"获取调试特权", GetLastError(), L"请尝试以管理员身份运行！");
	
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if(hProcess == INVALID_HANDLE_VALUE) print_err(L"打开进程", GetLastError(), L"请尝试管理员身份运行！");
	
	if(!fQuery){ //Set the Critical Flag
		fSuccess = CallNtSetInformationProcess(hProcess, fFlag);
		if(!fSuccess) print_err(L"设置关键进程时", GetLastError(), NULL);
	}
	
	else {
		ULONG bCritical = FALSE;
		fSuccess = CallNtQueryInformationProcess(hProcess, &bCritical);
		if(!fSuccess) print_err(L"询问进程关键度时", GetLastError(), NULL);
		else wprintf(L"指定的进程为%s。\n", bCritical?L"关键进程":L"普通进程");
	}
	
	return 0;
}

