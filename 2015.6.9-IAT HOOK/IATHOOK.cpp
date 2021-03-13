#include "StdAfx.h"
#include "head.h"
#include <windows.h>
#include "psapi.h"
#pragma comment(lib, "Psapi.Lib")
typedef int (WINAPI* Pmessagebox)(HWND, LPCTSTR, LPCTSTR, UINT);
Pmessagebox oldAddr;

#ifdef _UNICODE
#define _tprintf wprintf
#else
#define _tprintf printf
#endif
int WINAPI FakeMessagebox(HWND hWnd,          // handle to owner window
	LPCTSTR lpText,     // text in message box
	LPCTSTR lpCaption,  // message box title
	UINT uType)       // message box style
{
//	cout << "正在调用messagebox，" << "参数1 = " << hWnd << "，参数二 = " << lpText << ",参数三 = "
//		<< lpCaption << "，参数四 = " << uType << endl;
	_tprintf(TEXT("正在调用messagebox，参数1 = %d，参数二 = %s，参数三 = %s，参数四 = %d\n"), hWnd, lpText, lpCaption, uType);
	//MY_ASSERT(oldAddr);
	oldAddr(hWnd, lpText, lpCaption, uType);
	return 0;
}

int main()
{
	LPVOID pImageBuffer = NULL;
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_NT_HEADERS32 pImageNTHeader = NULL;
	PIMAGE_SECTION_HEADER pImageSectionHeader = NULL;

	// 获取进程信息
	MODULEINFO moduleInfo;
	MY_ASSERT(GetModuleInformation(GetCurrentProcess(),
		GetModuleHandle("USER32.DLL"), &moduleInfo, sizeof(moduleInfo)));
	pImageBuffer = malloc(moduleInfo.SizeOfImage);

	// 读取SizeOfImage大小的内存，放到pImageBuffer里面
	DWORD dwSizeRead = 0;
	MY_ASSERT(ReadProcessMemory(GetCurrentProcess(), moduleInfo.lpBaseOfDll,
		pImageBuffer, moduleInfo.SizeOfImage, &dwSizeRead));
	MY_ASSERT(moduleInfo.SizeOfImage == dwSizeRead);

	// 设定各种指针
	pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	MY_ASSERT(pImageDosHeader);
	MY_ASSERT((pImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE));
	pImageNTHeader =
		(PIMAGE_NT_HEADERS32)((PBYTE)pImageBuffer + pImageDosHeader->e_lfanew);
	MY_ASSERT(pImageNTHeader->FileHeader.SizeOfOptionalHeader == 0xe0);

	// 读取IAT表
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(
		(PBYTE)pImageBuffer +
		pImageNTHeader->OptionalHeader.DataDirectory[1].VirtualAddress);

	// 设定旧Messagebox指针
	oldAddr = (Pmessagebox)MessageBox;
	MY_ASSERT(oldAddr);

	while (pImportDescriptor->Name != 0 || pImportDescriptor->FirstThunk != 0)
	{
		printf("DLL name: %s\n",
			(PCHAR)((PBYTE)pImageBuffer + pImportDescriptor->Name));

		PDWORD pThunkData_IAT = NULL;

		pThunkData_IAT = (PDWORD)(
			(PBYTE)pImageBuffer + pImportDescriptor->FirstThunk);

		PIMAGE_IMPORT_BY_NAME pImportByName = NULL;

		puts("");
		printf("IAT表:\n");
		while (*pThunkData_IAT)
		{
			if ((int)oldAddr == *pThunkData_IAT)
			{
#ifdef _DEBUG
				printf("找到了！地址(*pThunkData_IAT)是0x%x\n", *pThunkData_IAT);
				printf("pThunkIAT = 0x%x\n", pThunkData_IAT);
#endif

				// 设定新地址
				DWORD dwSizeWritten = 0;
				DWORD t_addr = (DWORD)FakeMessagebox;

				// 获得需要修改的地址离基址的偏移
				DWORD offsetToFunAddr = (DWORD)pThunkData_IAT - (DWORD)pImageBuffer;
#ifdef _DEBUG
				printf("偏移是:0x%x\n", offsetToFunAddr);
#endif
				MY_ASSERT(WriteProcessMemory(GetCurrentProcess(), (LPVOID)((DWORD)moduleInfo.lpBaseOfDll + offsetToFunAddr),
					(LPVOID)(&t_addr), sizeof(DWORD), &dwSizeWritten));
				MY_ASSERT(dwSizeWritten == sizeof(DWORD));
				//((Pmessagebox)(*pThunkData_IAT))(0, TEXT("test"), TEXT("test"), 0);
			}
			//pImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pImageBuffer + *pThunkData_IAT);
			//MY_ASSERT(pImportByName);
			printf("第一个bit是0,*pThunkData_IAT = 0x%x\n", *pThunkData_IAT);
			pThunkData_IAT++;
		}

		puts("");
		pImportDescriptor++;  // 将pImportDescriptor向后移动
	}
	MessageBox(0, 0, 0, 0);
	MessageBox(0, TEXT("内容"), TEXT("标题"), 0);
	system("pause");
}

DWORD ReadPEFile(IN LPCSTR file_in, OUT LPVOID& pImageBuffer,
	PIMAGE_DOS_HEADER& pImageDosHeader, PIMAGE_NT_HEADERS32& pImageNTHeader,
	PIMAGE_SECTION_HEADER& pSectionHeader)
{
	FILE* fp;
	fp = fopen(file_in, "rb");
	if (!fp)
		EXIT_ERROR("fp == NULL!");
	DWORD file_size = 0;
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	LPVOID t = malloc(file_size);
	if ((fread(t, file_size, 1, fp) != 1) || t == NULL)
		EXIT_ERROR("fread error or malloc error!");

	pImageBuffer = t;
	MY_ASSERT(pImageBuffer);

	pImageDosHeader = (PIMAGE_DOS_HEADER)(pImageBuffer);
	MY_ASSERT(pImageDosHeader);
	MY_ASSERT((pImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE));

	pImageNTHeader =
		(PIMAGE_NT_HEADERS32)((PBYTE)pImageBuffer + pImageDosHeader->e_lfanew);
	if (pImageNTHeader->FileHeader.SizeOfOptionalHeader != 0xe0)
		EXIT_ERROR("this is not a 32-bit executable file.");

	pSectionHeader = (PIMAGE_SECTION_HEADER)(
		(PBYTE)pImageNTHeader + sizeof(IMAGE_NT_SIGNATURE) +
		sizeof(IMAGE_FILE_HEADER) + pImageNTHeader->FileHeader.SizeOfOptionalHeader);
	fclose(fp);
	return file_size;
}

DWORD RVA_TO_FOA(LPVOID pImageBuffer, PIMAGE_DOS_HEADER pImageDosHeader,
				 PIMAGE_NT_HEADERS32 pImageNTHeader,
				 PIMAGE_SECTION_HEADER pSectionHeader, IN DWORD RVA)
{
	if (RVA < pImageNTHeader->OptionalHeader.SizeOfHeaders)
		return RVA;
	
	for (int i = 0; i < pImageNTHeader->FileHeader.NumberOfSections; i++)
	{
		if (RVA >= pSectionHeader[i].VirtualAddress &&
			RVA < pSectionHeader[i].VirtualAddress +
			pSectionHeader[i].Misc.VirtualSize)
		{
			return (RVA - pSectionHeader[i].VirtualAddress +
				pSectionHeader[i].PointerToRawData);
		}
	}
	
	EXIT_ERROR("rva to foa failure!");
}

DWORD FOA_TO_RVA(LPVOID pImageBuffer, PIMAGE_DOS_HEADER pImageDosHeader,
				 PIMAGE_NT_HEADERS32 pImageNTHeader,
				 PIMAGE_SECTION_HEADER pSectionHeader, IN DWORD FOA)
{
	if (FOA < pImageNTHeader->OptionalHeader.SizeOfHeaders)
		return FOA;
	
	for (int i = 0; i < pImageNTHeader->FileHeader.NumberOfSections; i++)
	{
		if (FOA >= pSectionHeader[i].PointerToRawData &&
			FOA < pSectionHeader[i].PointerToRawData +
			pSectionHeader[i].Misc.VirtualSize)
		{
			return (FOA - pSectionHeader[i].PointerToRawData +
				pSectionHeader[i].VirtualAddress);
		}
	}
	
	EXIT_ERROR("foa to rva error!");
}