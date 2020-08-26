#pragma once
#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <windows.h>

#include <iostream>

using namespace std;

#define FILEPATH_IN "e:\\fg.exe"

#define EXIT_ERROR(x)                                 \
    do                                                \
{                                                 \
	cout << "error in line " << __LINE__ << endl; \
	cout << x << endl;                                    \
	cout << "errcode = " << GetLastError() << endl; \
	system("pause");                                   \
	exit(EXIT_FAILURE);                           \
} while (0)

#define FAIL_LOG(x)                                          \
    do                                                       \
{                                                        \
	cout << "test failure in line " << __LINE__ << endl; \
	cout << x;                                           \
	cout << "errcode = " << GetLastError() << endl; \
	getchar();                                           \
	exit(EXIT_FAILURE);                                  \
} while (0)

#define MY_ASSERT(x)                         \
    do                                       \
{                                        \
	if (!x)                              \
	EXIT_ERROR("ASSERTION failed!"); \
} while (0)

#define PRINT_RESULT(t_totaltest, t_successcount)            \
    do                                                       \
{                                                        \
	if (t_totaltest == t_successcount)                   \
	cout << "all tests passed!" << endl;             \
	else                                                 \
	cout << t_totaltest - t_successcount << "("      \
	<< (double)(t_totaltest - t_successcount) / \
	(double)t_totaltest * (double)100    \
	<< "%)tests falied!" << endl;               \
} while (0)

char g_NameOfNewSectionHeader[] = { 'Y', 'U', 'C', 'H', 'U' };

DWORD ReadPEFile(IN LPCSTR file_in, OUT LPVOID& pFileBuffer,
				 PIMAGE_DOS_HEADER& pDosHeader, PIMAGE_NT_HEADERS32& pNTHeader,
				 PIMAGE_SECTION_HEADER& pSectionHeader);

DWORD RVA_TO_FOA(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
				 PIMAGE_NT_HEADERS32 pNTHeader,
				 PIMAGE_SECTION_HEADER pSectionHeader, IN DWORD RVA);

DWORD FOA_TO_RVA(LPVOID pFileBuffer, PIMAGE_DOS_HEADER pDosHeader,
				 PIMAGE_NT_HEADERS32 pNTHeader,
    PIMAGE_SECTION_HEADER pSectionHeader, IN DWORD FOA);