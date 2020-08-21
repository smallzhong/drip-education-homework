#include "StdAfx.h"
// EnumProcessAndModules.cpp : Defines the entry point for the console application.
//
#include "windows.h"
#include "stdio.h"
#include "iostream"
#include "head.h"
char string_inject[] = "injectdll.dll";
#define MY_DEBUG
int main()
{
    int pid = 0;
    cout << "请输入要注入的进程的PID：";
    cin >> pid;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
        EXIT_ERROR("hProcess == NULL!");

    // else cout << hex << hProcess;

    // 在进程中分配内存
    LPVOID baseAddr = ::VirtualAllocEx(hProcess, NULL, sizeof(string_inject), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (baseAddr == NULL)
        EXIT_ERROR("VirtualAllocEx failure");

#ifdef MY_DEBUG
    printf("base address that VirtualAllocEx returns is 0x%x\n", (DWORD)baseAddr);
#endif

    // 写入内存
    DWORD NumberOfBytesWritten = 0;
    if (!WriteProcessMemory(hProcess, baseAddr, string_inject, sizeof(string_inject), &NumberOfBytesWritten))
        EXIT_ERROR("WriteProcessMemory failure");
#ifdef MY_DEBUG
    printf("NumberOfBytesWritten = 0x%x\n", NumberOfBytesWritten);
#endif

    // 创建远程线程
    HANDLE hRemoteThread = ::CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, /*TODO: */ baseAddr, 0, NULL);
    MY_ASSERT(hRemoteThread);

    // 3、等待线程函数结束， 获取线程退出码,即LoadLibrary的返回值，即dll的首地址
    WaitForSingleObject(hRemoteThread, -1);
    DWORD exitCode = 0;
    if (!GetExitCodeThread(hRemoteThread, &exitCode))
        EXIT_ERROR("GetExitCodeThread error!");
#ifdef MY_DEBUG
    printf("thread exitcode = 0x%x\n", exitCode);
    printf("errcode = %d\n", GetLastError());
#endif
    system("pause");
}
