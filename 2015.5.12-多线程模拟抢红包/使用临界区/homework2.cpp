// homework2.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"
#include "stdio.h"
#include "limits.h"
#include "stdlib.h"

char string_buffer1[110];
char string_buffer2[110];
char string_buffer3[110];
char string_buffer4[110];

HWND g_hwnd;
CRITICAL_SECTION cs; 
HANDLE hHandleArr[5];
int g_total = -1;
int g_num1 = 0;
int g_num2 = 0;
int g_num3 = 0;

BOOL CALLBACK MainDlgProc(HWND hwndDlg,   // handle to dialog box
                          UINT uMsg,      // message
                          WPARAM wParam,  // first message parameter
                          LPARAM lParam   // second message parameter
						  );

DWORD WINAPI ThreadProc1(LPVOID lpParameter);
DWORD WINAPI ThreadProc2(LPVOID lpParameter);
DWORD WINAPI ThreadProc3(LPVOID lpParameter);
DWORD WINAPI ThreadProc4(LPVOID lpParameter);

DWORD WINAPI MainThreadProc(LPVOID lpParameter);  // thread data

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     LPSTR lpCmdLine, int nCmdShow)
{
	InitializeCriticalSection(&cs);
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, MainDlgProc);
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
		case IDC_BUTTON1:
			//创建一个新的线程
			HANDLE hThread =
				::CreateThread(NULL, 0, MainThreadProc, NULL, 0, NULL);
		}
		return TRUE;
        case WM_CLOSE:
            EndDialog(hwndDlg, 0);
            exit(0);
            break;
    }
    return FALSE;
}

DWORD WINAPI MainThreadProc(LPVOID lpParameter)
{
	memset(hHandleArr, 0, sizeof(hHandleArr));
	GetWindowText(GetDlgItem(g_hwnd, IDC_EDIT_TOTAL), string_buffer1, 100);
	sscanf(string_buffer1, "%d", &g_total);
	hHandleArr[0] =
				::CreateThread(NULL, 0, ThreadProc1, NULL, 0, NULL);
	hHandleArr[1] =
				::CreateThread(NULL, 0, ThreadProc2, NULL, 0, NULL);
	hHandleArr[2] =
				::CreateThread(NULL, 0, ThreadProc3, NULL, 0, NULL);
	::WaitForMultipleObjects(3, hHandleArr, TRUE, -1); // 有一个线程结束说明抢红包过程结束
	::CloseHandle(hHandleArr[0]);
	::CloseHandle(hHandleArr[1]);
	::CloseHandle(hHandleArr[2]); // 防止内核对象泄漏
	g_total = -1;
	g_num1 = g_num2 = g_num3 = 0; // 设置为0，方便下一次抢红包
    return 0;
}

DWORD WINAPI ThreadProc1(LPVOID lpParameter)
{
	while (1)
	{
		EnterCriticalSection(&cs);
		if (g_total <= 0)
		{
			LeaveCriticalSection(&cs);
			break;
		}
		if (g_total >= 50)
		{
			g_total -= 50;
			g_num1 += 50;
		}
		else
		{
			g_num1 += g_total;
			g_total = 0;
		}
		sprintf(string_buffer1, "%d", g_total);
		sprintf(string_buffer2, "%d", g_num3);
		SetWindowText(GetDlgItem(g_hwnd, IDC_EDIT1), string_buffer2);
		SetWindowText(GetDlgItem(g_hwnd, IDC_EDIT_TOTAL), string_buffer1);
		LeaveCriticalSection(&cs);
		Sleep(50);
	}
	return 0;
}

DWORD WINAPI ThreadProc2(LPVOID lpParameter)
{
	while (1)
	{
		EnterCriticalSection(&cs);
		if (g_total <= 0)
		{
			LeaveCriticalSection(&cs);
			break;
		}
		if (g_total >= 50)
		{
			g_total -= 50;
			g_num2 += 50;
		}
		else
		{
			g_num2 += g_total;
			g_total = 0;
		}
		sprintf(string_buffer1, "%d", g_total);
		sprintf(string_buffer2, "%d", g_num2);
		SetWindowText(GetDlgItem(g_hwnd, IDC_EDIT2), string_buffer2);
		SetWindowText(GetDlgItem(g_hwnd, IDC_EDIT_TOTAL), string_buffer1);
		LeaveCriticalSection(&cs);
		Sleep(50);
	}
	return 0;
}

DWORD WINAPI ThreadProc3(LPVOID lpParameter)
{
	while (1)
	{
		EnterCriticalSection(&cs);
		if (g_total <= 0)
		{
			LeaveCriticalSection(&cs);
			break;
		}
		if (g_total >= 50)
			g_total -= 50, g_num3 += 50;
		else
		{
			g_num3 += g_total;
			g_total = 0;
		}
		sprintf(string_buffer1, "%d", g_total);
		sprintf(string_buffer2, "%d", g_num3);
		SetWindowText(GetDlgItem(g_hwnd, IDC_EDIT_TOTAL), string_buffer1);
		SetWindowText(GetDlgItem(g_hwnd, IDC_EDIT3), string_buffer2);
		LeaveCriticalSection(&cs);
		Sleep(50);
	}
	return 0;
}

