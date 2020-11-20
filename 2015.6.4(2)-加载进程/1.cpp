// LoadProcess_2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "stdlib.h"
#include <windows.h>

DWORD WINAPI InjectEntry(LPVOID lpParam)
{
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
    PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
    PDWORD OriginalFirstThunk = NULL;
    PDWORD FirstThunk = NULL;
    PBYTE FunctionName = NULL;
    DWORD dllNameAddr = 0;

    pDosHeader = (PIMAGE_DOS_HEADER)lpParam;
    pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)lpParam + pDosHeader->e_lfanew + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    pDataDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL32_HEADER - 128);
    pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((pDataDirectory + 1)->VirtualAddress + (DWORD)lpParam);
    while (pImportDescriptor->FirstThunk != 0)
    {
        DWORD dllNameAddr = pImportDescriptor->Name + (DWORD)lpParam;
        OriginalFirstThunk = (PDWORD)(pImportDescriptor->OriginalFirstThunk + (DWORD)lpParam);
        FirstThunk = (PDWORD)(pImportDescriptor->FirstThunk + (DWORD)lpParam);
        PDWORD oft = FirstThunk;

        //遍历
        while (OriginalFirstThunk[0] != 0)
        {

            if ((*OriginalFirstThunk >> 28) == 8)
            {
                DWORD orderNumber = *OriginalFirstThunk & 0x7fffffff;
                printf("按序号导入，序号：%x\n", orderNumber);
                *FirstThunk = (DWORD)GetProcAddress(LoadLibrary((char *)dllNameAddr), (char *)orderNumber);
            }
            else
            {
                pImportByName = (PIMAGE_IMPORT_BY_NAME)(*OriginalFirstThunk + (DWORD)lpParam);
                printf("按名字导入，Hint-Name:%x-%s\n", pImportByName->Hint, pImportByName->Name);
                *FirstThunk = (DWORD)GetProcAddress(LoadLibrary((char *)dllNameAddr), (char *)pImportByName->Name);
            }
            OriginalFirstThunk++;
            FirstThunk++;
        }
        pImportDescriptor++;
    }

    while (TRUE)
    {
        MessageBox(0, 0, 0, 0);
        Sleep(2000);
    }
    return 0;
}

void RestoreRelocation(IN LPVOID pImageBuffer, IN DWORD newImageBase)
{

    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_BASE_RELOCATION pRelocation = NULL;
    DWORD High4 = 0;
    DWORD Low12 = 0;
    PDWORD BlockIndexRVA = 0;
    DWORD NumberOfTerms = 0;
    DWORD oldImagebase = 0;

    pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageBuffer + pDosHeader->e_lfanew + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    pDataDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL32_HEADER - 128);

    pRelocation = (PIMAGE_BASE_RELOCATION)((pDataDirectory + 5)->VirtualAddress + (DWORD)pImageBuffer);

    oldImagebase = pOptionHeader->ImageBase;
    pOptionHeader->ImageBase = newImageBase;

    while (pRelocation->VirtualAddress != 0 && pRelocation->SizeOfBlock != 0)
    {
        //块中一共有几项
        NumberOfTerms = (pRelocation->SizeOfBlock - 8) / 2;
        PWORD value = (PWORD)((DWORD)pRelocation + 8);
        for (int i = 0; i < NumberOfTerms; i++)
        {
            High4 = *value >> 12;
            Low12 = *value & 0xfff;
            //printf("Index:%d  RVA:%x  High4:%x\n", i+2, BlockIndexRVA, High4);
            if (High4 == 3)
            {
                BlockIndexRVA = (PDWORD)((pRelocation->VirtualAddress + Low12) + (DWORD)pImageBuffer);
                *BlockIndexRVA = *BlockIndexRVA - oldImagebase + pOptionHeader->ImageBase;
            }
            value++;
        }
        pRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocation + pRelocation->SizeOfBlock);
    }
}

int main(int argc, char *argv[])
{

    //获取自身imagebase
    HMODULE pImageBuffer = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));

    //获取自身sizeofimage
    DWORD sizeOfImage = pOptionHeader->SizeOfImage;

    // 创建一个新的缓冲区，将自己复制进去
    LPVOID pNewImagebuffer = malloc(sizeOfImage);
    memset(pNewImagebuffer, 0, sizeOfImage);
    memcpy(pNewImagebuffer, pImageBuffer, sizeOfImage);

    //打开要注入的A进程
    HANDLE hProcess;
    DWORD pid = 0;
    printf("PID:");
    scanf("%d", &pid);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        printf("Open process failed!");
        return -1;
    }

    //在A进程中申请内存，大小就是SizeOfImage
    LPVOID pProcessVirtualAddr = VirtualAllocEx(hProcess, NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    //修复B的重定位表
    RestoreRelocation(pNewImagebuffer, DWORD(pProcessVirtualAddr));

    //将修复后的数据，复制到A的内存中
    DWORD byteWritten = 0;
    BOOL alreadyWrite = WriteProcessMemory(hProcess, pProcessVirtualAddr, pNewImagebuffer, sizeOfImage, &byteWritten);
    if (!alreadyWrite)
    {
        printf("can not write process memory!");
        return -1;
    }

    //计算函数在进程A中的地址 = 函数在当前进程的地址 - 当前进程的基址(imagebase) + 进程A中申请的基址
    DWORD funAddrInProcessA = (DWORD)InjectEntry - (DWORD)pImageBuffer + (DWORD)pProcessVirtualAddr;

    //创建行程线程,执行相应函数.
    HANDLE pThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)funAddrInProcessA, pProcessVirtualAddr, 0, NULL);
    WaitForSingleObject(pThread, -1);
    return 0;
}
