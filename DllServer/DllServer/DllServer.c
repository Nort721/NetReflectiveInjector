#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "DllServer.h"

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_PORT "2843"

int main(int argc, char** argv) {
    HANDLE hFile = NULL;
    DWORD dwLength = NULL;
    DWORD dwBytesRead = 0;
    LPVOID lpBuffer = NULL;

    if (argc < 2)
    {
        ERROR("Wrong usage. Try: DllServer.exe <target dll>");
        return 0;
    }

    char* cpDllFile = argv[1];

    hFile = CreateFileA(cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        ERROR_WITH_CODE("Failed to open the DLL file");
    dwLength = GetFileSize(hFile, NULL);
    if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
        ERROR_WITH_CODE("Failed to get the DLL file size");
    lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
    if (!lpBuffer)
        ERROR_WITH_CODE("Failed to alloc a buffer!");
    if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE)
        ERROR_WITH_CODE("Failed to read dll raw data");

    //unsigned char* byteData = (unsigned char*)lpBuffer;
    //for (int i = 0; i < dwBytesRead; ++i) {
    //    printf("%02X ", byteData[i]);
    //    if ((i + 1) % 16 == 0)
    //        printf("\n");
    //}
    //printf("\n");

    SOCKET ServerSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        ERROR_WITH_CODE("WSAStartup failed");
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    if (getaddrinfo(NULL, DEFAULT_PORT, &hints, &result) != 0) {
        WSACleanup();
        ERROR_WITH_CODE("Resolving server address & port failed");
    }

    // Create a SOCKET for the server to listen for client connections.
    ServerSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ServerSocket == INVALID_SOCKET) {
        freeaddrinfo(result);
        WSACleanup();
        ERROR_WITH_CODE("ServerSocket creation failed");
    }

    // Setup the TCP listening socket
    if (bind(ServerSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        freeaddrinfo(result);
        closesocket(ServerSocket);
        WSACleanup();
        ERROR_WITH_CODE("Bind failed");
    }

    printf("Listening to incoming requests . . .\n");
    freeaddrinfo(result);

    // Listen for incoming connections
    if (listen(ServerSocket, SOMAXCONN) == SOCKET_ERROR) {
        // Handle listen error
        closesocket(ServerSocket);
        WSACleanup();
        ERROR_WITH_CODE("Listen failed");
    }

    while (TRUE) {
        // Accept incoming connection
        ClientSocket = accept(ServerSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET) {
            closesocket(ServerSocket);
            WSACleanup();
            ERROR_WITH_CODE("Accept failed");
        }

        // Send data over the connection
        printf("Sending dll data\n");
        send(ClientSocket, lpBuffer, dwLength, 0);
    }

    // Clean up
    closesocket(ClientSocket);
    closesocket(ServerSocket);
    WSACleanup();

    return 0;
}
