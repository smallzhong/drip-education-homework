#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

CRITICAL_SECTION g_csX;
CRITICAL_SECTION g_csY;

DWORD WINAPI ThreadProc1(LPVOID lpParameter)
{
    for (int x = 0; x < 1000; x++)
    {
        EnterCriticalSection(&g_csX);
        EnterCriticalSection(&g_csY);
        Sleep(1000);
        printf("111111\n");
        LeaveCriticalSection(&g_csY);
        LeaveCriticalSection(&g_csX);
    }
    return 0;
}

DWORD WINAPI ThreadProc2(LPVOID lpParameter)
{
    for (int x = 0; x < 1000; x++)
    {
        EnterCriticalSection(&g_csY);
        EnterCriticalSection(&g_csX);
        Sleep(1000);
        printf("222222\n");
        LeaveCriticalSection(&g_csX);
        LeaveCriticalSection(&g_csY);
    }
    return 0;
}

int main()
{
    InitializeCriticalSection(&g_csX);
    InitializeCriticalSection(&g_csY);
    HANDLE hThread1 = ::CreateThread(NULL, 0, ThreadProc1, NULL, 0, NULL);
	
    //创建一个新的线程
    HANDLE hThread2 = ::CreateThread(NULL, 0, ThreadProc2, NULL, 0, NULL);
    ::CloseHandle(hThread1);
    ::CloseHandle(hThread2);
    Sleep(100000000);
}