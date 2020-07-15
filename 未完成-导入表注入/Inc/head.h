#pragma once
#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <windows.h>

#include <iostream>

using namespace std;
#pragma warning(disable : 4996)
#pragma warning(disable : 6011)
#define FILEPATH_IN "d:\\test.exe"
#define FILEPATH_OUT "e:\\out.exe"

#define EXIT_ERROR(x)                                                          \
    do                                                                         \
    {                                                                          \
        cout << "error in line " << __LINE__ << endl;                          \
        cout << x;                                                             \
        getchar();                                                             \
        exit(EXIT_FAILURE);                                                    \
    } while (0)

#define FAIL_LOG(x)                                                            \
    do                                                                         \
    {                                                                          \
        cout << "test failure in line " << __LINE__ << endl;                   \
        cout << x;                                                             \
        getchar();                                                             \
        exit(EXIT_FAILURE);                                                    \
    } while (0)

#define PRINT_RESULT(t_totaltest, t_successcount)                              \
    do                                                                         \
    {                                                                          \
        if (t_totaltest == t_successcount)                                     \
            cout << "all tests passed!" << endl;                               \
        else                                                                   \
            cout << t_totaltest - t_successcount << "("                        \
                 << (double)(t_totaltest - t_successcount) /                   \
                        (double)t_totaltest * (double)100                      \
                 << "%)tests falied!" << endl;                                 \
    } while (0)

char t_NameOfNewSectionHeader[6] = { 'Y', 'U', 'C', 'H', 'U', 'A' };

DWORD ReadPEFile(IN LPCSTR file_in, OUT LPVOID* pFileBuffer);
PIMAGE_NT_HEADERS32 GetNTHeader(LPVOID pFileBuffer,
    PIMAGE_DOS_HEADER* pDosHeader);
PIMAGE_DOS_HEADER GetDosHeader(LPVOID pFileBuffer);
size_t GetFileLength(LPVOID pFileBuffer);
bool RVA_TO_FOA(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
    PIMAGE_NT_HEADERS32 pNTHeader,
    PIMAGE_SECTION_HEADER pSectionHeader, IN DWORD RVA,
    OUT PDWORD FOA);

bool FOA_TO_RVA(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
    PIMAGE_NT_HEADERS32 pNTHeader,
    PIMAGE_SECTION_HEADER pSectionHeader, IN DWORD FOA,
    OUT PDWORD RVA);

DWORD GetRVAFunctionAddrByOrdinals(
    LPVOID pFileBuffer, DWORD ord);  // 返回需要查找的序号的函数对应的RVA

DWORD GetRVAFunctionAddrByName(LPVOID pFileBuffer, LPSTR name);

void CreateNewSection(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
    PIMAGE_NT_HEADERS32 pNTHeader,
    PIMAGE_SECTION_HEADER pFirstSectionHeader,
    size_t file_size, size_t size_of_new_section,
    LPSTR NameOfNewSetionHeader);

void SaveToFile(LPCSTR file_out, size_t file_size, IN LPVOID pFileBuffer);

void MoveRelocationTable(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
    PIMAGE_NT_HEADERS32 pNTHeader,
    PIMAGE_SECTION_HEADER pSectionHeader,
    DWORD add_to_location);

void PrintBindImportTable(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
    PIMAGE_NT_HEADERS32 pNTHeader,
    PIMAGE_SECTION_HEADER pSectionHeader);

void InjectImportTable(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
    PIMAGE_NT_HEADERS32 pNTHeader,
    PIMAGE_SECTION_HEADER pSectionHeader, size_t file_size);