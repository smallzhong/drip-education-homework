// 只对32位的，文件对齐和内存对齐都是0x1000的程序有效。

#include "head.h"

int main()
{
	LPVOID pFileBuffer = NULL;
	LPVOID pNewFileBuffer = NULL;
	DWORD file_size = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer)
		EXIT_ERROR("pfilebuffer == NULL");
	MallocAndSetToZero(file_size, &pNewFileBuffer, 1000); // 在最后填充一个节大小的0

	//memcpy(pNewFileBuffer, pFileBuffer, file_size);

	PIMAGE_DOS_HEADER pDosHeader = GetDosHeader(pFileBuffer);
	PIMAGE_NT_HEADERS32 pNTHeader = GetNTHeader(pFileBuffer, &pDosHeader);

	pNTHeader->FileHeader.NumberOfSections += 0x1; // 修改节的数量，新增一个节
	pNTHeader->OptionalHeader.SizeOfImage += 0x1000; // 修改映像装载到内存中后的大小SizeOfImage
	// 接下来开始新增节表
	PIMAGE_SECTION_HEADER pFirstSetionHeader = NULL;
	//pFirstSetionHeader = (PIMAGE_SECTION_HEADER)((DWORD)(pNTHeader->OptionalHeader) +
	//	pNTHeader->FileHeader.SizeOfOptionalHeader);
	pFirstSetionHeader = (PIMAGE_SECTION_HEADER)(
		(DWORD)pNTHeader + sizeof(IMAGE_NT_SIGNATURE) +
		sizeof(IMAGE_FILE_HEADER) + pNTHeader->FileHeader.SizeOfOptionalHeader);
	// 指向NT头的指针加上PE标志大小加上标准PE头大小加上可选PE头大小得到第一个节表的地址
	assert(pFirstSetionHeader);


	PIMAGE_SECTION_HEADER pApeendSectionHeader = NULL;
	// 指向第一个节表头的指针加上(节表数 * 节表大小)得到需要新增的节表的位置
	pApeendSectionHeader = pFirstSetionHeader + pNTHeader->FileHeader.NumberOfSections - 1; 
	// 因为刚刚把NumOfSetions加了一，现在要减一

	// 将第一个节表的内容复制到新增节表上面去
	memcpy(pApeendSectionHeader, pFirstSetionHeader, sizeof(IMAGE_SECTION_HEADER));
	// 修改该节表的名字
	memcpy(pApeendSectionHeader, NameOfNewSetionHeader, sizeof(NameOfNewSetionHeader));
	// 修改该节表中其他必要属性
	(pApeendSectionHeader->Misc).VirtualSize = 0x1000; // 对齐前的大小，设为1000即可
	// 为了修改VirtualAddress，要获取前一个节表的属性
	PIMAGE_SECTION_HEADER pLastSetionHeader = NULL;
	pLastSetionHeader = pApeendSectionHeader - 1;
	// 根据前一个节表的属性修改virtualAddress
	pApeendSectionHeader->VirtualAddress = pLastSetionHeader->VirtualAddress + pLastSetionHeader->SizeOfRawData;
	// 修改sizeofRawData
	pApeendSectionHeader->SizeOfRawData = 0x1000;

	// 更新PointerToRawData
	pApeendSectionHeader->PointerToRawData = pLastSetionHeader->PointerToRawData + pLastSetionHeader->SizeOfRawData;




	pApeendSectionHeader->Characteristics = pFirstSetionHeader->Characteristics | pLastSetionHeader->Characteristics;
	SaveToFile("e:\\1.exe", file_size + 0x1000, pFileBuffer);
	//SaveToFile(FILEPATH_OUT, file_size + 1000, pNewFileBuffer);
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
	return pDosHeader;
}

void SaveToFile(LPCSTR file_out, size_t file_size, IN LPVOID pNewFileBuffer)
{
	FILE* fp = fopen(file_out, "wb");
	if (!fp)
		EXIT_ERROR("fp == NULL");
	int t = fwrite(pNewFileBuffer, file_size, 1, fp);
	if (t != 1)
		EXIT_ERROR("t != 1");
	fclose(fp);
}

void MallocAndSetToZero(IN DWORD OriginFileSize, OUT LPVOID* pNewFileBuffer, size_t AppendSize)
{
	if (*pNewFileBuffer) EXIT_ERROR("pNewfilebuffer not null!");
	LPVOID tempBuffer;
	tempBuffer = malloc(OriginFileSize + AppendSize);
	if (tempBuffer == NULL)
		EXIT_ERROR("tempbuffer == NULL");

	memset(tempBuffer, 0, OriginFileSize + AppendSize);
	*pNewFileBuffer = tempBuffer;
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
