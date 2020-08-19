#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <windows.h>

#include <iostream>

using namespace std;
#pragma warning(disable : 4996)
#pragma comment(linker, "/subsystem:\"windows\"  /entry:\"mainCRTStartup\"")
int main()
{
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi;

    si.cb = sizeof(si);
    BOOL res = CreateProcess(
        TEXT("C:\\Program Files (x86)\\Tencent\\QQ\\Bin\\QQ.exe"),
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL, &si, &pi);
    TCHAR szTitle[MAX_PATH] = {0};
    HWND hwnd = ::FindWindow(TEXT("TXGuiFoundation"), TEXT("QQ"));
    for (int i = 0; i < 100; i++)
    {
        if (hwnd != NULL)
        {
            //修改窗口标题
            //::SetWindowText(hwnd, L"新的窗口标题");
            RECT r;
            ::GetWindowRect(hwnd, &r);
            ::SetCursorPos(r.left + 170, r.top + 295);
            mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0); //点下左键
            mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);   //松开左键
            keybd_event(97, 0, 0, 0);
            keybd_event(97, 0, KEYEVENTF_KEYUP, 0);
            Sleep(50);
            ::SetCursorPos(r.left + 170, r.top + 350);
            mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0); //点下左键
            mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);   //松开左键
            exit(0);
        }
        else
        {
            hwnd = ::FindWindow(TEXT("TXGuiFoundation"), TEXT("QQ"));
            Sleep(5);
        }
    }
    // 如果500ms还打不开，则失败
    MessageBox(0, TEXT("打开QQ失败"), TEXT("打开QQ失败"), 0);
    return 0;
}