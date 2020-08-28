// eeeeeeeeeeeeeee.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include <stdio.h>
#include <stdlib.h>
#include "haed.h"

char g_codePatch[0x200]; // 用来存放被NOP掉之前的代码
DWORD dwRetAddr;         // 用来存储需要返回的地址

DWORD Plus(DWORD x, DWORD y);
BOOL SetInlineHook(DWORD Addr, DWORD func, DWORD bytes);
BOOL UninstallInlineHook(DWORD Addr, DWORD bytes);

struct
{
    DWORD eax;
    DWORD ecx;
    DWORD edx;
    DWORD ebx;
} st_reg;

extern "C" __declspec(naked) VOID ProcFunc()
{
    // 保存现场
    __asm {
		pushad
		pushfd
    }

    // 获取寄存器的值
    __asm {
        mov st_reg.eax, eax mov st_reg.ecx, ecx mov st_reg.edx, edx mov st_reg.ebx, ebx}

    printf("eax = 0x%x, ecx = 0x%x, edx = 0x%x, ebx = 0x%x\n", st_reg.eax, st_reg.ecx, st_reg.edx, st_reg.ebx);

    // 恢复现场
    __asm {
		popfd
		popad
    }

    // 做原来函数做的事情
    __asm
    {
        push ebp
            mov ebp,
            esp
                sub esp,
            40h
    }

    // 跳回原函数
    __asm {
		jmp dwRetAddr
    }
}

int main(int argc, char *argv[])
{
    DWORD dwAddr = 0x4018F0;
    DWORD dwBytes = 6;
    SetInlineHook(dwAddr, 1, dwBytes);
    DWORD a = Plus(1, 2);
    printf("Plus(1, 2) = %d\n", a);
    UninstallInlineHook(dwAddr, dwBytes);
    printf("Plus(1, 2) = %d\n", a);
    system("pause");
    return 0;
}

// 0x4018F0 // 自己测试的时候要把这个地址根据自己电脑上显示的数据改动
DWORD Plus(DWORD x, DWORD y)
{
    return x + y;
}

BOOL SetInlineHook(DWORD Addr, DWORD func, DWORD bytes)
{
    // 判断是否合法
    MY_ASSERT(Addr && func && (bytes >= 6));

    // 更改操作权限，改为可写
    DWORD dwOldProtect = 0;
    VirtualProtect((LPVOID)Addr, bytes, PAGE_EXECUTE_READWRITE, &dwOldProtect);
#ifdef _DEBUG
    printf("dwOldProtect = 0x%d\n", dwOldProtect);
#endif

    // 保存原来的代码并NOP掉原来的代码
    memcpy(g_codePatch, (LPVOID)Addr, bytes);
    memset((LPVOID)Addr, 0x90, bytes);

    // 计算shellcode中E9后面的值
    // E9后面的值 = 要跳转的地址 - E9的地址 - 5
    DWORD dwJmpCode = 0;
    DWORD dwProcAddr = (DWORD)ProcFunc;
    dwJmpCode = dwProcAddr - Addr - 5;

    // 设置JMP,跳转到目标函数
    *((PBYTE)Addr) = 0xE9;
    *((PDWORD)(((PBYTE)Addr) + 1)) = dwJmpCode;

    // 修改HOOK状态
    dwRetAddr = Addr + bytes;

    return FALSE;
}

BOOL UninstallInlineHook(DWORD Addr, DWORD bytes)
{
    memcpy((LPVOID)Addr, g_codePatch, bytes);
    return TRUE;
}