#include "head.h"

int main()
{
    LPVOID pFileBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS32 pNTHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    DWORD file_size = ReadPEFile("f:\\fg_origin.exe", pFileBuffer, pDosHeader,
                                 pNTHeader, pSectionHeader);

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(
        (PBYTE)pFileBuffer +
        RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
                   pNTHeader->OptionalHeader.DataDirectory[1].VirtualAddress));

    while (pImportDescriptor->Name != 0 || pImportDescriptor->FirstThunk != 0)
    {
        printf("DLL name: %s\n",
               (PCHAR)(PBYTE)pFileBuffer + RVA_TO_FOA(pFileBuffer, pDosHeader,
                                                      pNTHeader, pSectionHeader,
                                                      pImportDescriptor->Name));

        PDWORD pThunkData_INT = NULL;
        PDWORD pThunkData_IAT = NULL;
        pThunkData_INT = (PDWORD)(
            (PBYTE)pFileBuffer +
            RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
                       pImportDescriptor->OriginalFirstThunk));
        pThunkData_IAT =
            (PDWORD)((PBYTE)pFileBuffer +
                     RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader,
                                pSectionHeader, pImportDescriptor->FirstThunk));

        PIMAGE_IMPORT_BY_NAME pImportByName = NULL;

        printf("INT表:\n");
        while (*pThunkData_INT)
        {
            if ((*pThunkData_INT) & 0x80000000)
            {
                printf("按序号导出：0x%x\n", (*pThunkData_INT) & 0x7fffffff);
            }
            else
            {
                pImportByName = (PIMAGE_IMPORT_BY_NAME)(
                    (PBYTE)pFileBuffer +
                    RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader,
                               pSectionHeader, (*pThunkData_INT) & 0x7fffffff));
                MY_ASSERT(pImportByName);
                printf("按名字导出：%s\n", pImportByName->Name);
            }
            pThunkData_INT++;
        }

        puts("");
        printf("IAT表:\n");
        while (*pThunkData_IAT)
        {
            if ((*pThunkData_IAT) & 0x80000000)
            {
                printf("按序号导出：0x%x\n", (*pThunkData_IAT) & 0x80000000);
            }
            else
            {
                pImportByName = (PIMAGE_IMPORT_BY_NAME)(
                    (PBYTE)pFileBuffer + RVA_TO_FOA(pFileBuffer, pDosHeader,
                                                    pNTHeader, pSectionHeader,
                                                    *pThunkData_IAT));
                MY_ASSERT(pImportByName);
                printf("按名字导出：%s\n", pImportByName->Name);
            }
            pThunkData_IAT++;
        }

        puts("");
        pImportDescriptor++;  // 将pImportDescriptor向后移动
    }
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