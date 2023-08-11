#pragma once
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#define INDEX_TARGET_PROCESS_ID 1
#define ERROR_WITH_CODE(e) (printf("[-] ERROR: %s, 0x%x\r\n", e, GetLastError()))
#define ERROR(e) (printf("[-] ERROR: %s\r\n", e))
#define INFO_WITH_CODE(e) (printf("[*] INFO: %s, 0x%x\r\n", e, GetLastError()))
#define INFO(e) (printf("[*] INFO: %s\r\n", e))
#define SUCCESS(e) (printf("[+] SUCCESS: %s\r\n", e))
#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)
HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength,
	LPVOID lpParameter);
DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer);
DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress);