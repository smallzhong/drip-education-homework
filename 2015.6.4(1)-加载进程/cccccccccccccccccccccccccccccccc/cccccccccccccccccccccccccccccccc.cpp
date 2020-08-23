// cccccccccccccccccccccccccccccccc.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "stdlib.h"
#include "head.h"

#define FILEPATH_IN "c:\\bbbbbbbbbbbbbbbbbbbbbb.exe"
#define MY_DEBUG

int main()
{	
#ifdef MY_DEBUG
	cout << hex;
#endif
	// 1、将自己进程的ImageBase设置一个较大的值，让自己的程序在高空运行.

	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS32 pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	

	// 2、将要执行的进程读取进来，按照进程的ImageBase和SizeOfImage分配空间							
	DWORD dwFileSize = ReadPEFile(FILEPATH_IN, pFileBuffer, pDosHeader,
		pNTHeader, pSectionHeader);
	DWORD dwImageBase = pNTHeader->OptionalHeader.ImageBase;
	DWORD dwSizeOfImage = pNTHeader->OptionalHeader.SizeOfImage;
	HANDLE hCurrentProcess = GetCurrentProcess();

	// 先用VirtualAllocEx保留空间
	LPVOID pProcessAddr = ::VirtualAllocEx(hCurrentProcess, (LPVOID)dwImageBase, 
		dwSizeOfImage, 
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pProcessAddr)
	{
		printf("errcode = %d\n", GetLastError());
		EXIT_ERROR("VirtualAllocEx 分配内存空间失败！");
	}

	// 再用VirtualAlloc申请内存
	//pProcessAddr = VirtualAlloc((LPVOID)dwImageBase, dwSizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE); 
	
	// 3、拉伸目标程序			
	LPVOID pImageBuffer = NULL;
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	MY_ASSERT(pImageBuffer); 

	// 4、修复IAT表
	PIMAGE_IMPORT_DESCRIPTOR pImageDescriptor_After = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pImageBuffer + 
		((pNTHeader->OptionalHeader.DataDirectory[1].VirtualAddress)));
	while (pImageDescriptor_After->FirstThunk != 0 || pImageDescriptor_After->OriginalFirstThunk != 0)
	{
		DbgPrintf("dll name:%s\n", (PCHAR)pImageBuffer + pImageDescriptor_After->Name);

		PDWORD pThunkData_INT = NULL;
		PDWORD pThunkData_IAT = NULL;
		pThunkData_INT = (PDWORD)(((PBYTE)pImageBuffer + pImageDescriptor_After->OriginalFirstThunk));
		//DbgPrintf("pImageDescriptor_After->OriginalFirstThunk = 0x%x\n", pImageDescriptor_After->OriginalFirstThunk);
		pThunkData_IAT = (PDWORD)(((PBYTE)pImageBuffer + pImageDescriptor_After->FirstThunk));
		
		PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
		DbgPrintf("INT表:\n");

		// 遍历INT,IAT表，根据INT表修复IAT表
		while (*pThunkData_INT)
		{
			if ((*pThunkData_INT) & 0x80000000)
			{
				DbgPrintf("按序号导出：0x%x\n", (*pThunkData_INT) & 0x7fffffff);
				EXIT_ERROR("int表中有按序号导出的函数(这个应该不可能触发((");
			}
			else
			{
				pImportByName =
					(PIMAGE_IMPORT_BY_NAME)(((PBYTE)pImageBuffer + ((*pThunkData_INT) & 0x7fffffff)));
					//(PIMAGE_IMPORT_BY_NAME)(((PBYTE)pFileBuffer + ((*pThunkData_INT) & 0x7fffffff)));
				//DbgPrintf("0x%x\n", ((*pThunkData_INT) & 0x7fffffff));
				MY_ASSERT(pImportByName);
				DbgPrintf("按名字导出：%s\n", pImportByName->Name);

				char string_buffer[0x200];
				memset(string_buffer, 0, 0x200);
				int t_ct = 0;
				while (pImportByName->Name[t_ct])
				{
					string_buffer[t_ct] = pImportByName->Name[t_ct];
					t_ct ++ ;
				}
				
				(*pThunkData_IAT) = (DWORD)GetProcAddress(LoadLibrary((PCHAR)pImageBuffer + pImageDescriptor_After->Name), 
					string_buffer);
				if ((*pThunkData_IAT) == NULL)
					EXIT_ERROR("(*pThunkData_IAT) == NULL");
			}
			pThunkData_INT ++ , pThunkData_IAT ++ ;
		}
		

		pImageDescriptor_After ++ ;
	}
	
	// 5. 将修复后的程序贴到当前进程中
	memset(pProcessAddr, 0, dwSizeOfImage);
	DWORD BytesWritten = 0;
	memcpy(pProcessAddr, pImageBuffer, dwSizeOfImage);
	MY_ASSERT((*((PWORD)pProcessAddr)) == IMAGE_DOS_SIGNATURE);
/*	if (!WriteProcessMemory(hCurrentProcess, pProcessAddr, pImageBuffer, dwSizeOfImage, &BytesWritten))
		EXIT_ERROR("WriteProcessMemory failure!");
	MY_ASSERT(BytesWritten == dwSizeOfImage);
#ifdef MY_DEBUG
	cout << "byteswritten = 0x" << BytesWritten << endl;
#endif*/

	// 6、跳转到入口执行
	DWORD t_oep = pNTHeader->OptionalHeader.AddressOfEntryPoint + pNTHeader->OptionalHeader.ImageBase;
	__asm{
		jmp t_oep
	}
//	system("pause");
	return 0;
}

DWORD CopyFileBufferToImageBuffer(PVOID pFileBuffer, PVOID *pImageBuffer)
{
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_NT_HEADERS pImageNtHeader = NULL;
	PIMAGE_FILE_HEADER pImageFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pImageSectionHeaderGroup = NULL;
	DWORD ImageBufferSize = 0;
	DWORD i = 0;
	
	// DOS头
	pImageDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	
	// 标准PE
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
	
	// 可选PE
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	
	//节表组
	pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);
	
	//获取ImageBufffer的内存大小
	ImageBufferSize = pImageOptionalHeader->SizeOfImage;
	
	//为pImageBuffer分配内存空间
	*pImageBuffer = (PVOID)malloc(ImageBufferSize);
	
	if (*pImageBuffer == NULL)
	{
		printf("malloc failed");
		return -1;
	}
	
	//清零
	memset(*pImageBuffer, 0, ImageBufferSize);
	
	// 拷贝头+节表
	memcpy(*pImageBuffer, pFileBuffer, pImageOptionalHeader->SizeOfHeaders);
	
	//循环拷贝节表
	for (i = 0; i < pImageFileHeader->NumberOfSections; i++)
	{
		memcpy(
			(PVOID)((DWORD)*pImageBuffer + pImageSectionHeaderGroup[i].VirtualAddress), // 要拷贝的位置 ImageBuffer中的每个节数据的偏移位置
			(PVOID)((DWORD)pFileBuffer + pImageSectionHeaderGroup[i].PointerToRawData), // 被拷贝的位置是 Filebuffer中的每个节数据的偏移位置
			pImageSectionHeaderGroup[i].SizeOfRawData									// 被拷贝的大小为 每个节数据的文件对齐大小
			);
	}
	
	return 0;
}

void AddNewSec(OUT LPVOID* pNewFileBuffer, IN LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
	PIMAGE_NT_HEADERS32 pNTHeader,
	PIMAGE_SECTION_HEADER pSectionHeader, DWORD file_size, DWORD dwAddSize)
{
	PIMAGE_FILE_HEADER pImageFileHeader =
		(PIMAGE_FILE_HEADER)((PBYTE)pDosHeader + pDosHeader->e_lfanew + 4);

	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)(
		(PBYTE)pImageFileHeader + sizeof(IMAGE_FILE_HEADER));

	if (((PBYTE)pImageOptionalHeader->SizeOfHeaders -
		((PBYTE)pDosHeader->e_lfanew + IMAGE_SIZEOF_FILE_HEADER +
			pImageFileHeader->SizeOfOptionalHeader +
			40 * pImageFileHeader->NumberOfSections)) < 80)
		EXIT_ERROR("空间不足，新增节表失败！");

	DWORD numOfSec = pImageFileHeader->NumberOfSections;
	// 1) 添加一个新的节(可以copy一份)
	memcpy(
		(LPVOID)(pSectionHeader + numOfSec), // 需要新增的位置
		(LPVOID)(pSectionHeader), // 第一个节
		sizeof(IMAGE_SECTION_HEADER)
	); // 将第一个节（代码节）拷贝

	// 2) 在新增节后面 填充一个节大小的000
	memset((LPVOID)(pSectionHeader + numOfSec + 1), 0, sizeof(IMAGE_SECTION_HEADER));

	// 3) 修改PE头中节的数量
	pImageFileHeader->NumberOfSections += 1;

	// 4) 修改sizeOfImage的大小
	pImageOptionalHeader->SizeOfImage += 0x1000;

	// 5）修正新增节表的属性

	// 修改该节表的名字
	memcpy((LPVOID)(pSectionHeader + numOfSec), g_NameOfNewSectionHeader, sizeof(g_NameOfNewSectionHeader));

	// 修改该节表中其他必要属性
	(pSectionHeader + numOfSec)->Misc.VirtualSize = 0x1000; // 对齐前的大小，设为1000即可

	// 根据前一个节表的属性修改virtualAddress
	DWORD t_Add = 0; // (pSectionHeader + numOfSec - 1)->VirtualAddress 加上 t_Add 为VirtualAddress

	if ((pSectionHeader + numOfSec - 1)->Misc.VirtualSize < (pSectionHeader + numOfSec - 1)->SizeOfRawData)
	{ // 如果VirtualSize小于SizeOfRawData
		t_Add = (pSectionHeader + numOfSec - 1)->SizeOfRawData;
	}
	else
	{
		if (((pSectionHeader + numOfSec - 1)->Misc.VirtualSize % 0x1000) == 0) // 如果其能被0x1000整除
			t_Add = (pSectionHeader + numOfSec - 1)->Misc.VirtualSize;
		else
			t_Add = ((((pSectionHeader + numOfSec - 1)->Misc.VirtualSize / 0x1000) + 1)) * 0x1000;
	}
	MY_ASSERT(t_Add);
	(pSectionHeader + numOfSec)->VirtualAddress = (pSectionHeader + numOfSec - 1)->VirtualAddress
		+ t_Add;

	// 修改sizeofRawData
	(pSectionHeader + numOfSec)->SizeOfRawData = 0x1000;

	// 更新PointerToRawData
	(pSectionHeader + numOfSec)->PointerToRawData = (pSectionHeader + numOfSec - 1)->PointerToRawData +
		(pSectionHeader + numOfSec - 1)->SizeOfRawData;

	// (pSectionHeader + numOfSec)->Characteristics = (pSectionHeader->Characteristics | (pSectionHeader + numOfSec - 1)->Characteristics);

	// 6) 在原有数据的最后，新增一个节的数据(内存对齐的整数倍) (复制到新的LPVOID中去)
	*pNewFileBuffer = malloc(file_size + dwAddSize);
	memcpy(*pNewFileBuffer, pFileBuffer, file_size);
}

DWORD ReadPEFile(IN LPCSTR file_in, OUT LPVOID& pFileBuffer,
	PIMAGE_DOS_HEADER& pDosHeader, PIMAGE_NT_HEADERS32& pNTHeader,
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

	pFileBuffer = t;
	MY_ASSERT(pFileBuffer);

	pDosHeader = (PIMAGE_DOS_HEADER)(pFileBuffer);
	MY_ASSERT(pDosHeader);
	MY_ASSERT((pDosHeader->e_magic == IMAGE_DOS_SIGNATURE));

	pNTHeader =
		(PIMAGE_NT_HEADERS32)((PBYTE)pFileBuffer + pDosHeader->e_lfanew);
	if (pNTHeader->FileHeader.SizeOfOptionalHeader != 0xe0)
		EXIT_ERROR("this is not a 32-bit executable file.");

	pSectionHeader = (PIMAGE_SECTION_HEADER)(
		(PBYTE)pNTHeader + sizeof(IMAGE_NT_SIGNATURE) +
		sizeof(IMAGE_FILE_HEADER) + pNTHeader->FileHeader.SizeOfOptionalHeader);
	fclose(fp);
	return file_size;
}

DWORD RVA_TO_FOA(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
	PIMAGE_NT_HEADERS32 pNTHeader,
	PIMAGE_SECTION_HEADER pSectionHeader, IN DWORD RVA)
{
	if (RVA < pNTHeader->OptionalHeader.SizeOfHeaders)
		return RVA;

	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
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

DWORD FOA_TO_RVA(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
	PIMAGE_NT_HEADERS32 pNTHeader,
	PIMAGE_SECTION_HEADER pSectionHeader, IN DWORD FOA)
{
	if (FOA < pNTHeader->OptionalHeader.SizeOfHeaders)
		return FOA;

	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
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