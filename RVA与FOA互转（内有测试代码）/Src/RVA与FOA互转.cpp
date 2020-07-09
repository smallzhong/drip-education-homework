#include "head.h"

int main()
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS32 pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	ReadPEFile(FILEPATH_IN, &pFileBuffer);
	pDosHeader = GetDosHeader(pFileBuffer);
	pNTHeader = GetNTHeader(pFileBuffer, &pDosHeader);
	pSectionHeader = (PIMAGE_SECTION_HEADER)(
		(DWORD)pNTHeader + sizeof(IMAGE_NT_SIGNATURE) +
		sizeof(IMAGE_FILE_HEADER) + pNTHeader->FileHeader.SizeOfOptionalHeader);
	assert(pSectionHeader);
	// 设定好DOS头指针、NT头指针和节表指针

	Test(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader);
}

void Test(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
	PIMAGE_NT_HEADERS32 pNTHeader, PIMAGE_SECTION_HEADER pSectionHeader)
{
	int totaltest = 0;
	int successcount = 0;

	DWORD RVA = pSectionHeader[0].VirtualAddress + 0x1000;
	DWORD FOA = -1;
	totaltest++;
	if (RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader, RVA,
		&FOA))
		if (FOA == 8192)
			successcount++;
		else
			FAIL_LOG("RVA TO FOA CONVERSION ADDRESS ERROR!");
	else
		FAIL_LOG("RVA TO FOA ERROR!");

	FOA = 8192;
	totaltest++;
	if (FOA_TO_RVA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader, FOA, &RVA))
		if (RVA == pSectionHeader[0].VirtualAddress + 0x1000)
			successcount++;
		else
			FAIL_LOG("FOA TO RVA CONVERSION ADDRESS ERROR!");
	else
		FAIL_LOG("FOA TO RVA ERROR!");
	cout << "totaltest = " << totaltest << endl
		<< "successcount = " << successcount << endl;
	PRINT_RESULT(totaltest, successcount);
}

bool FOA_TO_RVA(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
	PIMAGE_NT_HEADERS32 pNTHeader,
	PIMAGE_SECTION_HEADER pSectionHeader, IN DWORD FOA,
	OUT PDWORD RVA)
{
	if (FOA < pNTHeader->OptionalHeader.SizeOfHeaders ||
		pNTHeader->OptionalHeader.SectionAlignment ==
		pNTHeader->OptionalHeader.FileAlignment)
	{
		*RVA = FOA;
		return true;
	}

	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
	{
		if (FOA >= pSectionHeader[i].PointerToRawData &&
			FOA < pSectionHeader[i].PointerToRawData +
			pSectionHeader[i].Misc.VirtualSize)
		{
			*RVA = pSectionHeader[i].VirtualAddress + FOA -
				pSectionHeader[i].PointerToRawData;
			return true;
		}
	}
	return false;
}

bool RVA_TO_FOA(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
	PIMAGE_NT_HEADERS32 pNTHeader,
	PIMAGE_SECTION_HEADER pSectionHeader, IN DWORD RVA,
	OUT PDWORD FOA)
{
	if (RVA < pNTHeader->OptionalHeader
		.SizeOfHeaders)  // 如果是在头部，在节之前，说明并不需要拉伸，RVA = FOA
	{
		*FOA = RVA;
		return true;
	}
	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections;
		i++)  // 循环每一个节表
		if (RVA >= pSectionHeader[i].VirtualAddress &&
			RVA < pSectionHeader[i].VirtualAddress +
			pSectionHeader[i].Misc.VirtualSize)
		{
			*FOA = pSectionHeader[i].PointerToRawData + RVA -
				pSectionHeader[i].VirtualAddress;
			return true;
		}

	return false;  // 如果一直没有找到，返回false
}

size_t GetFileLength(LPVOID pFileBuffer)
{
	return _msize(pFileBuffer);
}

DWORD ReadPEFile(IN LPCSTR file_in, OUT LPVOID* pFileBuffer)
{
	FILE* fp;
	fp = fopen(file_in, "rb");
	if (fp == NULL)
		EXIT_ERROR("fp == NULL");

	LPVOID ptempFileBuffer;
	fseek(fp, 0, SEEK_END);
	DWORD file_size = ftell(fp);
	ptempFileBuffer = malloc(file_size);
	fseek(fp, 0, SEEK_SET); // 将指针指回文件头
	fread(ptempFileBuffer, file_size, 1, fp);
	if (ptempFileBuffer == NULL)
		EXIT_ERROR("ptempfilebuffer == NULL");

	*pFileBuffer = ptempFileBuffer; // 赋值，完成工作

	fclose(fp); // 收尾
	return file_size;
}

PIMAGE_NT_HEADERS32 GetNTHeader(LPVOID pFileBuffer, PIMAGE_DOS_HEADER* pDosHeader)
{
	PIMAGE_NT_HEADERS32 pNTHeader32 = NULL;
	pNTHeader32 = (PIMAGE_NT_HEADERS32)((DWORD)pFileBuffer + (*pDosHeader)->e_lfanew);
	if (!pNTHeader32)
		EXIT_ERROR("null pointer!");
	if (pNTHeader32->Signature != IMAGE_NT_SIGNATURE)
		EXIT_ERROR("nt header error!signature not match!");
	return pNTHeader32;
}

PIMAGE_DOS_HEADER GetDosHeader(LPVOID pFileBuffer)
{
	if (pFileBuffer == NULL)
		EXIT_ERROR("pfilebuffer == NULL");
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
		EXIT_ERROR("the first word is not MZ!");

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (!pDosHeader || pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		EXIT_ERROR("null pointer or file not executable!");
	return pDosHeader;
}

