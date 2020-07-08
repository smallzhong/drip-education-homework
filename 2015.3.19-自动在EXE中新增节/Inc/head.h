#pragma once
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <assert.h>

using namespace std;
#pragma warning(disable:4996)
#define FILEPATH_IN "e:\\2.exe"
//#define FILEPATH_OUT "D:\\C++\\cyberpet_new.exe"
#define EXIT_ERROR(x)                                                          \
    do                                                                         \
    {                                                                          \
        cout << "error in line " << __LINE__ << endl;                          \
        cout << x;                                                             \
        getchar();                                                             \
        exit(EXIT_FAILURE);                                                    \
    } while (0)

const char NameOfNewSetionHeader[] = {
    'Y', 'U', 'C', 'H', 'U'
};

DWORD ReadPEFile(IN LPCSTR file_in, OUT LPVOID* pFileBuffer);
void MallocAndSetToZero(IN DWORD OriginFileSize, OUT LPVOID * pNewFileBuffer, size_t AppendSize);
void SaveToFile(LPCSTR file_out, size_t file_size, IN LPVOID pNewFileBuffer);
PIMAGE_DOS_HEADER GetDosHeader(LPVOID pFileBuffer);
PIMAGE_NT_HEADERS32 GetNTHeader(LPVOID pFileBuffer, PIMAGE_DOS_HEADER *pDosHeader);