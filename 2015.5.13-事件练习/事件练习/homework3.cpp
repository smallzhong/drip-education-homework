// homework3.cpp : Defines the entry point for the application.
//

#include "StdAfx.h"
#include "resource.h"
#include "stdio.h"
#include "stdlib.h"

HWND g_hwnd;
HANDLE hThread;
HANDLE g_hEvent; // 事件句柄
HWND hEdit1;		
HWND hEdit2;		
HWND hEdit3;		
HWND hEdit4;		

BOOL CALLBACK MainDlgProc(HWND hwndDlg,   // handle to dialog box
                          UINT uMsg,      // message
                          WPARAM wParam,  // first message parameter
                          LPARAM lParam   // second message parameter
);

DWORD WINAPI ThreadProcMain(LPVOID lpParameter); 
DWORD WINAPI ThreadProc1(LPVOID lpParameter); 
DWORD WINAPI ThreadProc2(LPVOID lpParameter); 
DWORD WINAPI ThreadProc3(LPVOID lpParameter); 
DWORD WINAPI ThreadProc4(LPVOID lpParameter); 

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, MainDlgProc);
	return 0;
}

BOOL CALLBACK MainDlgProc(HWND hwndDlg,   // handle to dialog box
                          UINT uMsg,      // message
                          WPARAM wParam,  // first message parameter
                          LPARAM lParam   // second message parameter
						  )
{
    switch (uMsg)
    {
	case WM_INITDIALOG:
		g_hwnd = hwndDlg;
	/*	hThread = ::CreateThread(NULL, 0, ThreadProcMain, NULL, 0, NULL);
		::CloseHandle(hThread);*/
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON1:
			::CreateThread(NULL, 0, ThreadProc1, NULL, 0, NULL);
		}
		return TRUE;

    case WM_CLOSE:
        EndDialog(hwndDlg, 0);
        exit(0);
        break;
	}
    return FALSE;
}

DWORD WINAPI ThreadProcMain(LPVOID lpParameter)
{
/*	SetWindowText(GetDlgItem(g_hwnd, IDC_EDIT1), TEXT("0"));
	SetWindowText(GetDlgItem(g_hwnd, IDC_EDIT2), TEXT("0"));
	SetWindowText(GetDlgItem(g_hwnd, IDC_EDIT3), TEXT("0"));
	SetWindowText(GetDlgItem(g_hwnd, IDC_EDIT4), TEXT("0"));*/
	return 0;
}

DWORD WINAPI ThreadProc1(LPVOID lpParameter)
{
	hEdit1 = GetDlgItem(g_hwnd, IDC_EDIT1);
	hEdit2 = GetDlgItem(g_hwnd, IDC_EDIT2);
	hEdit3 = GetDlgItem(g_hwnd, IDC_EDIT3);
	hEdit4 = GetDlgItem(g_hwnd, IDC_EDIT4);

	//默认安全属性  手动设置未通知状态(TRUE)  初始状态未通知 没有名字 
	// g_hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	// 默认安全属性  自动设置通知状态(FALSE)  初始状态未通知 没有名字 
	g_hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	HANDLE hThreadArr[5];
	hThreadArr[0] = ::CreateThread(NULL, 0, ThreadProc2, NULL, 0, NULL);
	hThreadArr[1] = ::CreateThread(NULL, 0, ThreadProc3, NULL, 0, NULL);
	hThreadArr[2] = ::CreateThread(NULL, 0, ThreadProc4, NULL, 0, NULL);

	// SetWindowText(GetDlgItem(g_hwnd, IDC_EDIT1), "1000");
	TCHAR szBuffer[10] = {0};
	for (int i = 0; i <= 1000; i ++ )
	{
		sprintf(szBuffer, "%d", i);
		SetWindowText(hEdit1, szBuffer);
		Sleep(1);
	}

	SetEvent(g_hEvent); // 设置事件为已通知

	WaitForMultipleObjects(3, hThreadArr, TRUE, INFINITE);  
	//等待线程结束 销毁内核对象
	CloseHandle(hThreadArr[0]);  		
	CloseHandle(hThreadArr[1]);		
	CloseHandle(hThreadArr[2]);	
	CloseHandle(g_hEvent);  
	return 0;
}

DWORD WINAPI ThreadProc2(LPVOID lpParameter)
{
	TCHAR szBuffer[10] = {0};

	//当事件变成已通知时 
	WaitForSingleObject(g_hEvent, INFINITE);
	GetWindowText(hEdit1,szBuffer,10);			
	
	SetWindowText(hEdit2, szBuffer);			
	Sleep(1000);
	SetEvent(g_hEvent);
	return 0;
}

DWORD WINAPI ThreadProc3(LPVOID lpParameter)
{
	TCHAR szBuffer[10] = {0};
	
	//当事件变成已通知时 
	WaitForSingleObject(g_hEvent, INFINITE);
	GetWindowText(hEdit1,szBuffer,10);			
	SetWindowText(hEdit3, szBuffer);	
	Sleep(1000);
	SetEvent(g_hEvent);
	return 0;
}

DWORD WINAPI ThreadProc4(LPVOID lpParameter)
{
	TCHAR szBuffer[10] = {0};
	
	//当事件变成已通知时
	WaitForSingleObject(g_hEvent, INFINITE);
	GetWindowText(hEdit1,szBuffer,10);
	SetWindowText(hEdit4, szBuffer);
	Sleep(1000);
	SetEvent(g_hEvent);
	return 0;
}