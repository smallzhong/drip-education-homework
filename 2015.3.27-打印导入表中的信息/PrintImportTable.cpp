#include "head.h"

int main()
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS32 pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	DWORD file_size = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	pDosHeader = GetDosHeader(pFileBuffer);
	pNTHeader = GetNTHeader(pFileBuffer, &pDosHeader);
	pSectionHeader = (PIMAGE_SECTION_HEADER)(
		(DWORD)pNTHeader + sizeof(IMAGE_NT_SIGNATURE) +
		sizeof(IMAGE_FILE_HEADER) + pNTHeader->FileHeader.SizeOfOptionalHeader);
	assert(pSectionHeader);
	// 设定好DOS头指针、NT头指针和节表指针

	DWORD export_directory_RVA =
		pNTHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
	DWORD export_directory_FOA = 0;
	RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
		export_directory_RVA, &export_directory_FOA);

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor =
		(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + export_directory_FOA);
	while (1)
	{
		if (!pImportDescriptor->TimeDateStamp && !pImportDescriptor->FirstThunk)
			break;
		DWORD name_FOA = 0;
		RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
			pImportDescriptor->Name, &name_FOA);

		cout << "*********";
		printf("%s", (PCHAR)(DWORD)pFileBuffer + name_FOA);
		cout << "*********" << endl;

		DWORD INTAddr_FOA = 0;
		DWORD IATAddr_FOA = 0;
		RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
			pImportDescriptor->OriginalFirstThunk, &INTAddr_FOA);
		RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
			pImportDescriptor->FirstThunk, &IATAddr_FOA);
		assert(INTAddr_FOA & IATAddr_FOA);
		PDWORD pThunkData_INT = NULL;
		PDWORD pThunkData_IAT = NULL;
		pThunkData_INT = (PDWORD)((DWORD)pFileBuffer + INTAddr_FOA);
		pThunkData_IAT = (PDWORD)((DWORD)pFileBuffer + IATAddr_FOA);
		while (*pThunkData_INT && *pThunkData_IAT)
		{
			if (*pThunkData_INT >> 31)  // 是序号
			{
				*pThunkData_INT &= 0x7fffffff;  // 把最高位去掉
				cout << "INT:ordinal:" << *pThunkData_INT;
			}
			else
			{
				DWORD import_by_name_FOA = 0;
				RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
					*pThunkData_INT, &import_by_name_FOA);
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(
					(DWORD)pFileBuffer + import_by_name_FOA);
				printf("INT:%s", pImportByName->Name);
			}
			if (*pThunkData_IAT >> 31)  // 是序号
			{
				*pThunkData_IAT &= 0x7fffffff;  // 把最高位去掉
				cout << "      IAT:ordinal:" << *pThunkData_IAT << endl;
			}
			else
			{
				DWORD import_by_name_FOA = 0;
				RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
					*pThunkData_IAT, &import_by_name_FOA);
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(
					(DWORD)pFileBuffer + import_by_name_FOA);
				printf("      IAT:%s\n", pImportByName->Name);
			}
			pThunkData_INT++, pThunkData_IAT++;
		}
		pImportDescriptor += 1;
		cout << endl << endl;
	}
}

void MoveRelocationTable(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
	PIMAGE_NT_HEADERS32 pNTHeader,
	PIMAGE_SECTION_HEADER pSectionHeader,
	DWORD add_to_location)
{
	DWORD fore_relocation_table_addr_RVA =
		pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
		.VirtualAddress;
	if (fore_relocation_table_addr_RVA == 0)
		EXIT_ERROR("there is no relocation table in this pe file!");

	DWORD fore_relocation_table_addr_FOA = 0;
	RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
		fore_relocation_table_addr_RVA, &fore_relocation_table_addr_FOA);
	PIMAGE_BASE_RELOCATION pForeBaseRelocation = (PIMAGE_BASE_RELOCATION)(
		(DWORD)pFileBuffer + fore_relocation_table_addr_FOA);
	assert(pForeBaseRelocation);

	// 开始遍历重定向表，并memcpy到新增的节中
	PIMAGE_BASE_RELOCATION pAfterBaseRelocation =
		(PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + add_to_location);
	while (1)
	{
		if (pForeBaseRelocation->SizeOfBlock ==
			0 /*&& pForeBaseRelocation->VirtualAddress == 0*/)
			break;

#if 1
		int num_of_addr = (pForeBaseRelocation->SizeOfBlock - 8) / 2;
		cout << "********************" << endl
			<< "RVA:" << hex << pForeBaseRelocation->VirtualAddress << endl;
		cout << "里面所存地址个数:" << num_of_addr << endl;
		PDWORD t_pAddr = NULL;
		t_pAddr = (PDWORD)((DWORD)pForeBaseRelocation + 8);

		for (int i = 0; i < num_of_addr; i++)
		{
			if ((t_pAddr[i] & 0x3000) == 0x3000)  // 判断高三位是否为0011
				cout << hex
				<< (t_pAddr[i] & 0xfff) +
				pForeBaseRelocation->VirtualAddress
				<< endl;
			else
				cout << "the first 4 bits are not 0011!" << endl;
		}

#endif

		memcpy(pAfterBaseRelocation, pForeBaseRelocation,
			pForeBaseRelocation
			->SizeOfBlock);  // 根据SizeOfBlock将一整块复制过去
		pForeBaseRelocation = (PIMAGE_BASE_RELOCATION)(
			(DWORD)pForeBaseRelocation + pForeBaseRelocation->SizeOfBlock);
		pAfterBaseRelocation = (PIMAGE_BASE_RELOCATION)(
			(DWORD)pAfterBaseRelocation + pAfterBaseRelocation->SizeOfBlock);
	}
	memset(pAfterBaseRelocation, 0, 8);  // 在最后补上8个0

	DWORD t_NewRelocationTableAddr_RVA = 0;
	FOA_TO_RVA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
		add_to_location, &t_NewRelocationTableAddr_RVA);
	pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
		.VirtualAddress = t_NewRelocationTableAddr_RVA;
}

void CreateNewSection(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
	PIMAGE_NT_HEADERS32 pNTHeader,
	PIMAGE_SECTION_HEADER pFirstSectionHeader,
	size_t file_size, size_t size_of_new_section,
	LPSTR NameOfNewSetionHeader)
{
	PIMAGE_SECTION_HEADER pNewSectionHeader =
		pFirstSectionHeader + pNTHeader->FileHeader.NumberOfSections;

	if (pNTHeader->OptionalHeader.SizeOfHeaders -
		(pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) +
			pNTHeader->FileHeader.NumberOfSections *
			sizeof(IMAGE_SECTION_HEADER)) <
		sizeof(IMAGE_SECTION_HEADER) *
		2)  // 判断最后一个节表末尾是否有能存放两个节表的空闲空间
		EXIT_ERROR("not enough space to add  section header!");

	memset(pNewSectionHeader + 1, 0,
		sizeof(IMAGE_SECTION_HEADER));  // 在添加的节后面填充0

	pNTHeader->FileHeader.NumberOfSections += 1;
	pNTHeader->OptionalHeader.SizeOfImage += size_of_new_section;  // 修正PE头

	realloc(pFileBuffer,
		file_size + size_of_new_section * 2);  // 在末尾增加需要增加的大小
// memset((PBYTE)pFileBuffer + size_of_new_section, 0,
// pNTHeader->OptionalHeader.FileAlignment);
// 再增加一个文件对齐大小的0

	memcpy(pNewSectionHeader, pFirstSectionHeader,
		sizeof(IMAGE_SECTION_HEADER));

	memcpy(pNewSectionHeader, NameOfNewSetionHeader,
		sizeof(NameOfNewSetionHeader));

	pNewSectionHeader->Misc.VirtualSize = size_of_new_section;

	PIMAGE_SECTION_HEADER t_LastSectionHeader = pNewSectionHeader - 1;
	pNewSectionHeader->PointerToRawData =
		t_LastSectionHeader->PointerToRawData +
		t_LastSectionHeader->SizeOfRawData;
	pNewSectionHeader->SizeOfRawData = size_of_new_section;
	pNewSectionHeader->VirtualAddress = t_LastSectionHeader->VirtualAddress +
		t_LastSectionHeader->SizeOfRawData;
}

void SaveToFile(LPCSTR file_out, size_t file_size, IN LPVOID pFileBuffer)
{
	FILE* fp = fopen(file_out, "wb");
	if (!fp)
		EXIT_ERROR("fp == NULL");
	int t = fwrite(pFileBuffer, _msize(pFileBuffer), 1, fp);
	if (t != 1)
		EXIT_ERROR("t != 1");
	fclose(fp);
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
