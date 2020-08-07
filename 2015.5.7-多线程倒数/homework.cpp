// homework.cpp : Defines the entry point for the application.
//


#include "Stdafx.h"
#include "stdio.h"
#include "stdlib.h"
#include "limits.h"
#include "resource.h"

HWND g_hwnd;

BOOL CALLBACK MainDlgProc(HWND hwndDlg,   // handle to dialog box
                          UINT uMsg,      // message
                          WPARAM wParam,  // first message parameter
                          LPARAM lParam   // second message parameter
);

DWORD WINAPI ThreadProc(LPVOID lpParameter);  // thread data

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     LPSTR lpCmdLine, int nCmdShow)
{
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG), NULL, MainDlgProc);
    return 0;
}

BOOL CALLBACK MainDlgProc(HWND hwndDlg,   // handle to dialog box
                          UINT uMsg,      // message
                          WPARAM wParam,  // first message parameter
                          LPARAM lParam   // second message parameter
)
{
    g_hwnd = hwndDlg;
    switch (uMsg)
    {
        case WM_INITDIALOG:
            return TRUE;
        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDC_BUTTON:
                    //创建一个新的线程
                    HANDLE hThread =
                        ::CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);

                    //如果不在其他的地方引用它 关闭句柄
                    ::CloseHandle(hThread);
            }
            return TRUE;
        case WM_CLOSE:
            EndDialog(hwndDlg, 0);
            exit(0);
            break;
    }
    return FALSE;
}

DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
    TCHAR string_buffer1[35], string_buffer2[35];
    memset(string_buffer1, 0, sizeof(string_buffer1)),
        memset(string_buffer2, 0, sizeof(string_buffer2));
    GetWindowText(GetDlgItem(g_hwnd, IDC_EDIT_ADD), string_buffer1, 30);
    GetWindowText(GetDlgItem(g_hwnd, IDC_EDIT_MINUS), string_buffer2, 30);
    DWORD num1, num2;
    num1 = num2 = 0;
    sscanf(string_buffer1, "%d", &num1);
    sscanf(string_buffer2, "%d", &num2);
	while (1)
	{
		Sleep(1000);
		num1++;
		num2--;
		sprintf(string_buffer1, "%d", num1);
		SetWindowText(GetDlgItem(g_hwnd, IDC_EDIT_ADD), string_buffer1);

		sprintf(string_buffer2, "%d", num2);
		SetWindowText(GetDlgItem(g_hwnd, IDC_EDIT_MINUS), string_buffer2);
		if (num1 == INT_MAX || num2 == INT_MIN)
			break;
	}

    return 0;
}