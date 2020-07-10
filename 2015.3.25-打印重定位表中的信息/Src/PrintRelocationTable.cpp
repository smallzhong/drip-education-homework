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

	DWORD RelocationTableAddr_RVA =
		pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
		.VirtualAddress;
	DWORD RelocationTableAddr_FOA = 0;
	RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
		RelocationTableAddr_RVA, &RelocationTableAddr_FOA);
	if (RelocationTableAddr_FOA == 0)
		EXIT_ERROR("this executable file does not have relocation table!");
	// cout << "DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]:" << endl;
	cout << "VirtualAddress:" << hex
		<< pNTHeader->OptionalHeader
		.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
		.VirtualAddress
		<< endl;

	cout << "Size:"
		<< pNTHeader->OptionalHeader
		.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
		.Size
		<< endl;

	PIMAGE_BASE_RELOCATION pRelocationTable =
		(PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + RelocationTableAddr_FOA);
	while (1)
	{
		if (pRelocationTable->SizeOfBlock == 0 &&
			pRelocationTable->VirtualAddress == 0)
			break;
		int num_of_addr = (pRelocationTable->SizeOfBlock - 8) / 2;
		cout << "********************" << endl
			<< "RVA:" << hex << pRelocationTable->VirtualAddress << endl;
		cout << "里面所存地址个数:" << num_of_addr << endl;
		PDWORD t_pAddr = NULL;
		t_pAddr = (PDWORD)((DWORD)pRelocationTable + 8);

		for (int i = 0; i < num_of_addr; i++)
		{
			if (!((t_pAddr[i] & 0x3000) ^ 0x3000))  // 判断高三位是否为0011
				cout << hex
				<< (t_pAddr[i] & 0xfff) + pRelocationTable->VirtualAddress
				<< endl;
			else
				cout << "the first 4 bits are not 0011!" << endl;
		}

		pRelocationTable = (PIMAGE_BASE_RELOCATION)(
			(DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
	}
}

DWORD GetRVAFunctionAddrByName(LPVOID pFileBuffer, LPSTR name)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS32 pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	pDosHeader = GetDosHeader(pFileBuffer);
	pNTHeader = GetNTHeader(pFileBuffer, &pDosHeader);
	pSectionHeader = (PIMAGE_SECTION_HEADER)(
		(DWORD)pNTHeader + sizeof(IMAGE_NT_SIGNATURE) +
		sizeof(IMAGE_FILE_HEADER) + pNTHeader->FileHeader.SizeOfOptionalHeader);
	assert(pSectionHeader);
	// 设定好DOS头指针、NT头指针和节表指针

	DWORD ExportDirectoryAddr = -1;
	if (!(ExportDirectoryAddr = pNTHeader->OptionalHeader
		.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
		.VirtualAddress))
		EXIT_ERROR("there is no export table in this pe file!");
	DWORD ExportDirectoryAddr_FOA = -1;
	RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
		ExportDirectoryAddr,
		&ExportDirectoryAddr_FOA);  // 将导出表地址的RVA转换为FOA

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	pExportDirectory =
		(PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + ExportDirectoryAddr_FOA);

	DWORD FunctionTableAddr = NULL;
	DWORD NameTableAddr = NULL;
	DWORD OrdinalTableAddr = NULL;

	RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
		pExportDirectory->AddressOfFunctions, &FunctionTableAddr);
	RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
		pExportDirectory->AddressOfNames, &NameTableAddr);
	RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
		pExportDirectory->AddressOfNameOrdinals, &OrdinalTableAddr);

	PDWORD arr_fun = NULL;
	PDWORD arr_name = NULL;
	PWORD arr_ord = NULL;
	arr_fun = (PDWORD)((DWORD)pFileBuffer +
		FunctionTableAddr);  // 得到指向AddressOfFunction的指针
	arr_name = (PDWORD)((DWORD)pFileBuffer +
		NameTableAddr);  // 得到指向AddressOfNames的指针
	arr_ord = (PWORD)((DWORD)pFileBuffer +
		OrdinalTableAddr);  // 得到指向AddressOfNameOrdinal的指针

	int ord_in_name_table = 0;
	for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
	{
		DWORD t_NameAddr_FOA = 0;
		RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
			arr_name[i], &t_NameAddr_FOA);

		if (!strcmp((char*)((DWORD)pFileBuffer + t_NameAddr_FOA), name))
		{
			ord_in_name_table = i;
			break;
		}
	}
	if (!ord_in_name_table)  // 如果一直没有找到
		EXIT_ERROR("there is no function with this name!");
	WORD ord_in_function_table = arr_ord[ord_in_name_table];
	return arr_fun[ord_in_function_table];
}

DWORD GetRVAFunctionAddrByOrdinals(LPVOID pFileBuffer, DWORD ord)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS32 pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	pDosHeader = GetDosHeader(pFileBuffer);
	pNTHeader = GetNTHeader(pFileBuffer, &pDosHeader);
	pSectionHeader = (PIMAGE_SECTION_HEADER)(
		(DWORD)pNTHeader + sizeof(IMAGE_NT_SIGNATURE) +
		sizeof(IMAGE_FILE_HEADER) + pNTHeader->FileHeader.SizeOfOptionalHeader);
	assert(pSectionHeader);
	// 设定好DOS头指针、NT头指针和节表指针

	DWORD ExportDirectoryAddr = -1;
	if (!(ExportDirectoryAddr = pNTHeader->OptionalHeader
		.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
		.VirtualAddress))
		EXIT_ERROR("there is no export table in this pe file!");
	DWORD ExportDirectoryAddr_FOA = -1;
	RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
		ExportDirectoryAddr,
		&ExportDirectoryAddr_FOA);  // 将导出表地址的RVA转换为FOA

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	pExportDirectory =
		(PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + ExportDirectoryAddr_FOA);

	DWORD FunctionTableAddr = NULL;
	RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
		pExportDirectory->AddressOfFunctions, &FunctionTableAddr);

	PDWORD arr_fun = NULL;
	arr_fun = (PDWORD)((DWORD)pFileBuffer +
		FunctionTableAddr);  // 得到指向AddressOfFunction的指针

	return arr_fun[ord - pExportDirectory->Base];
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
	if (RVA <
		pNTHeader->OptionalHeader
		.SizeOfHeaders)  // 如果是在头部，在节之前，说明并不需要拉伸，RVA
						 // = FOA
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
	fseek(fp, 0, SEEK_SET);  // 将指针指回文件头
	fread(ptempFileBuffer, file_size, 1, fp);
	if (ptempFileBuffer == NULL)
		EXIT_ERROR("ptempfilebuffer == NULL");

	*pFileBuffer = ptempFileBuffer;  // 赋值，完成工作

	fclose(fp);  // 收尾
	return file_size;
}

PIMAGE_NT_HEADERS32 GetNTHeader(LPVOID pFileBuffer,
	PIMAGE_DOS_HEADER* pDosHeader)
{
	PIMAGE_NT_HEADERS32 pNTHeader32 = NULL;
	pNTHeader32 =
		(PIMAGE_NT_HEADERS32)((DWORD)pFileBuffer + (*pDosHeader)->e_lfanew);
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
