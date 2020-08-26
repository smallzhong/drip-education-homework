#include "head.h"

int main()
{
    LPVOID pFileBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS32 pNTHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    DWORD file_size = ReadPEFile("d:\\test.exe", pFileBuffer, pDosHeader,
                                 pNTHeader, pSectionHeader);

    DWORD foa =
        RVA_TO_FOA(pFileBuffer, pDosHeader, pNTHeader, pSectionHeader,
                   pNTHeader->OptionalHeader.DataDirectory[2].VirtualAddress);
    DWORD next_VirtualAddress =
        pNTHeader->OptionalHeader.DataDirectory[2]
            .VirtualAddress; // 设定foa和next_VirtualAddress

    PIMAGE_RESOURCE_DIRECTORY prd1_backup = (PIMAGE_RESOURCE_DIRECTORY)(
        (PBYTE)pFileBuffer + foa); // 为以后相对位置的换算留备份
    PIMAGE_RESOURCE_DIRECTORY prd1 = prd1_backup;
    MY_ASSERT(prd1);

    int num1 = prd1->NumberOfNamedEntries + prd1->NumberOfIdEntries;

    PIMAGE_RESOURCE_DIRECTORY_ENTRY prdentry1 =
        (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(prd1 + 1);
    for (int i = 0; i < num1; i++)
    {
        PIMAGE_RESOURCE_DIRECTORY prd2 = (PIMAGE_RESOURCE_DIRECTORY)(
            (PBYTE)prd1_backup + (prdentry1->OffsetToData & 0x7fffffff));

        int num2 = prd2->NumberOfIdEntries + prd2->NumberOfNamedEntries;
        cout << "num2 = " << num2 << endl;
        PIMAGE_RESOURCE_DIRECTORY_ENTRY prdentry2 =
            (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(prd2 + 1);

        for (int i = 0; i < num2; i++)
        {
            PIMAGE_RESOURCE_DIRECTORY prd3 = (PIMAGE_RESOURCE_DIRECTORY)(
                (PBYTE)prd1_backup + (prdentry2->OffsetToData & 0x7fffffff));
            int num3 = prd3->NumberOfIdEntries + prd3->NumberOfNamedEntries;

            PIMAGE_RESOURCE_DIRECTORY_ENTRY prdentry3 =
                (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(prd3 + 1);

            printf("ID = %d\n", prdentry2->NameOffset);
            for (int i = 0; i < num3; i++)
            {
                //printf("NameIsString%d\n", 400000 - ((DWORD)pFileBuffer - (DWORD)prd1_backup + (prdentry1->OffsetToData & 0x7fffffff)));
                PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)((PBYTE)prd1_backup + (prdentry3->OffsetToData & 0x7fffffff));
                printf("VirtualAddress = %x\n", pDataDir->VirtualAddress);
                printf("size = %x\n", pDataDir->Size);
                prdentry3++;
            }

            prdentry2++;
        }
        cout << "------------" << endl;
        prdentry1++;
    }
}

DWORD ReadPEFile(IN LPCSTR file_in, OUT LPVOID &pFileBuffer,
                 PIMAGE_DOS_HEADER &pDosHeader, PIMAGE_NT_HEADERS32 &pNTHeader,
                 PIMAGE_SECTION_HEADER &pSectionHeader)
{
    FILE *fp;
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