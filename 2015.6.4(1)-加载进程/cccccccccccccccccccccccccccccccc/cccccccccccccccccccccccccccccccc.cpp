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
	// 1�����Լ����̵�ImageBase����һ���ϴ��ֵ�����Լ��ĳ����ڸ߿�����.

	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS32 pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	

	// 2����Ҫִ�еĽ��̶�ȡ���������ս��̵�ImageBase��SizeOfImage����ռ�							
	DWORD dwFileSize = ReadPEFile(FILEPATH_IN, pFileBuffer, pDosHeader,
		pNTHeader, pSectionHeader);
	DWORD dwImageBase = pNTHeader->OptionalHeader.ImageBase;
	DWORD dwSizeOfImage = pNTHeader->OptionalHeader.SizeOfImage;
	HANDLE hCurrentProcess = GetCurrentProcess();

	// ����VirtualAllocEx�����ռ�
	LPVOID pProcessAddr = ::VirtualAllocEx(hCurrentProcess, (LPVOID)dwImageBase, 
		dwSizeOfImage, 
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pProcessAddr)
	{
		printf("errcode = %d\n", GetLastError());
		EXIT_ERROR("VirtualAllocEx �����ڴ�ռ�ʧ�ܣ�");
	}

	// ����VirtualAlloc�����ڴ�
	//pProcessAddr = VirtualAlloc((LPVOID)dwImageBase, dwSizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE); 
	
	// 3������Ŀ�����			
	LPVOID pImageBuffer = NULL;
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	MY_ASSERT(pImageBuffer); 

	// 4���޸�IAT��
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
		DbgPrintf("INT��:\n");

		// ����INT,IAT������INT���޸�IAT��
		while (*pThunkData_INT)
		{
			if ((*pThunkData_INT) & 0x80000000)
			{
				DbgPrintf("����ŵ�����0x%x\n", (*pThunkData_INT) & 0x7fffffff);
				EXIT_ERROR("int�����а���ŵ����ĺ���(���Ӧ�ò����ܴ���((");
			}
			else
			{
				pImportByName =
					(PIMAGE_IMPORT_BY_NAME)(((PBYTE)pImageBuffer + ((*pThunkData_INT) & 0x7fffffff)));
					//(PIMAGE_IMPORT_BY_NAME)(((PBYTE)pFileBuffer + ((*pThunkData_INT) & 0x7fffffff)));
				//DbgPrintf("0x%x\n", ((*pThunkData_INT) & 0x7fffffff));
				MY_ASSERT(pImportByName);
				DbgPrintf("�����ֵ�����%s\n", pImportByName->Name);

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
	
	// 5. ���޸���ĳ���������ǰ������
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

	// 6����ת�����ִ��
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
	
	// DOSͷ
	pImageDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	
	// ��׼PE
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
	
	// ��ѡPE
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	
	//�ڱ���
	pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);
	
	//��ȡImageBufffer���ڴ��С
	ImageBufferSize = pImageOptionalHeader->SizeOfImage;
	
	//ΪpImageBuffer�����ڴ�ռ�
	*pImageBuffer = (PVOID)malloc(ImageBufferSize);
	
	if (*pImageBuffer == NULL)
	{
		printf("malloc failed");
		return -1;
	}
	
	//����
	memset(*pImageBuffer, 0, ImageBufferSize);
	
	// ����ͷ+�ڱ�
	memcpy(*pImageBuffer, pFileBuffer, pImageOptionalHeader->SizeOfHeaders);
	
	//ѭ�������ڱ�
	for (i = 0; i < pImageFileHeader->NumberOfSections; i++)
	{
		memcpy(
			(PVOID)((DWORD)*pImageBuffer + pImageSectionHeaderGroup[i].VirtualAddress), // Ҫ������λ�� ImageBuffer�е�ÿ�������ݵ�ƫ��λ��
			(PVOID)((DWORD)pFileBuffer + pImageSectionHeaderGroup[i].PointerToRawData), // ��������λ���� Filebuffer�е�ÿ�������ݵ�ƫ��λ��
			pImageSectionHeaderGroup[i].SizeOfRawData									// �������Ĵ�СΪ ÿ�������ݵ��ļ������С
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
		EXIT_ERROR("�ռ䲻�㣬�����ڱ�ʧ�ܣ�");

	DWORD numOfSec = pImageFileHeader->NumberOfSections;
	// 1) ���һ���µĽ�(����copyһ��)
	memcpy(
		(LPVOID)(pSectionHeader + numOfSec), // ��Ҫ������λ��
		(LPVOID)(pSectionHeader), // ��һ����
		sizeof(IMAGE_SECTION_HEADER)
	); // ����һ���ڣ�����ڣ�����

	// 2) �������ں��� ���һ���ڴ�С��000
	memset((LPVOID)(pSectionHeader + numOfSec + 1), 0, sizeof(IMAGE_SECTION_HEADER));

	// 3) �޸�PEͷ�нڵ�����
	pImageFileHeader->NumberOfSections += 1;

	// 4) �޸�sizeOfImage�Ĵ�С
	pImageOptionalHeader->SizeOfImage += 0x1000;

	// 5�����������ڱ������

	// �޸ĸýڱ������
	memcpy((LPVOID)(pSectionHeader + numOfSec), g_NameOfNewSectionHeader, sizeof(g_NameOfNewSectionHeader));

	// �޸ĸýڱ���������Ҫ����
	(pSectionHeader + numOfSec)->Misc.VirtualSize = 0x1000; // ����ǰ�Ĵ�С����Ϊ1000����

	// ����ǰһ���ڱ�������޸�virtualAddress
	DWORD t_Add = 0; // (pSectionHeader + numOfSec - 1)->VirtualAddress ���� t_Add ΪVirtualAddress

	if ((pSectionHeader + numOfSec - 1)->Misc.VirtualSize < (pSectionHeader + numOfSec - 1)->SizeOfRawData)
	{ // ���VirtualSizeС��SizeOfRawData
		t_Add = (pSectionHeader + numOfSec - 1)->SizeOfRawData;
	}
	else
	{
		if (((pSectionHeader + numOfSec - 1)->Misc.VirtualSize % 0x1000) == 0) // ������ܱ�0x1000����
			t_Add = (pSectionHeader + numOfSec - 1)->Misc.VirtualSize;
		else
			t_Add = ((((pSectionHeader + numOfSec - 1)->Misc.VirtualSize / 0x1000) + 1)) * 0x1000;
	}
	MY_ASSERT(t_Add);
	(pSectionHeader + numOfSec)->VirtualAddress = (pSectionHeader + numOfSec - 1)->VirtualAddress
		+ t_Add;

	// �޸�sizeofRawData
	(pSectionHeader + numOfSec)->SizeOfRawData = 0x1000;

	// ����PointerToRawData
	(pSectionHeader + numOfSec)->PointerToRawData = (pSectionHeader + numOfSec - 1)->PointerToRawData +
		(pSectionHeader + numOfSec - 1)->SizeOfRawData;

	// (pSectionHeader + numOfSec)->Characteristics = (pSectionHeader->Characteristics | (pSectionHeader + numOfSec - 1)->Characteristics);

	// 6) ��ԭ�����ݵ��������һ���ڵ�����(�ڴ�����������) (���Ƶ��µ�LPVOID��ȥ)
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