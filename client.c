#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>


// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


#define BUFFER_SIZE 1024
#define DEFAULT_PORT "27015"
#define THREAD_COUNT 2
#define SEND_THREAD 0
#define RECV_THREAD 1
#define MAX_NAME_LEN 32


// Enable Virtual Terminal Processing for colored output
inline void EnableVTMode() {
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hOut == INVALID_HANDLE_VALUE) return;

	DWORD dwMode = 0;
	if (!GetConsoleMode(hOut, &dwMode)) return;

	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode(hOut, dwMode);
}

// Thread functions for sending and receiving messages
DWORD __stdcall ClientSendMessage(LPVOID lpParam) {
	SOCKET connectSocket = (SOCKET)lpParam;
	char sendBuffer[BUFFER_SIZE];

	while (1) {
		if (!fgets(sendBuffer, BUFFER_SIZE, stdin))
			break;

		size_t len = strlen(sendBuffer);
		if (len > 0 && sendBuffer[len - 1] == '\n')
			sendBuffer[len - 1] = '\0';

		if (strcmp(sendBuffer, "exit") == 0) {
			shutdown(connectSocket, SD_SEND);
			break;
		}

		if (send(connectSocket, sendBuffer, (int)strlen(sendBuffer), 0) == SOCKET_ERROR) {
			printf("send failed: %d\n", WSAGetLastError());
			break;
		}
		
	}
	shutdown(connectSocket, SD_SEND);
	return 0;
}

DWORD __stdcall ClientRecieveMessage(LPVOID lpParam) {
	SOCKET connectSocket = (SOCKET)lpParam;
	char receiveBuffer[BUFFER_SIZE];
	int receiveBufferLength = BUFFER_SIZE;

	while (1) {
		int iResult = recv(connectSocket, receiveBuffer, receiveBufferLength, 0);
		if (iResult > 0) {
			receiveBuffer[iResult] = '\0';
			printf("%s\n", receiveBuffer);
			fflush(stdout);
		}
		else if (iResult == 0) {
			printf("\nServer closed connection\n");
			return 1;
		}
		else {
			printf("\nrecv failed: %d\n", WSAGetLastError());
			return 1;
		}
	}
	shutdown(connectSocket, SD_SEND);
	return 0;
}


int __cdecl main(int argc, char **argv)
{
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;

	HANDLE threads[THREAD_COUNT];

	char userName[MAX_NAME_LEN];


	EnableVTMode();

	// Validate the parameters
	if (argc != 2) {
		printf("usage: %s server-name\n", argv[0]);
		return 1;
	}

	// Initialize Winsock
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup failed with error: %d\n", WSAGetLastError());
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	if (getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result) != 0) {
		printf("getaddrinfo failed with error: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

		if (ConnectSocket == INVALID_SOCKET) {
			printf("Error at socket(): %ld\n", WSAGetLastError());
			freeaddrinfo(result);
			WSACleanup();
			return 1;
		}

		// Connect to server.
		if (connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) 
		{
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}

	printf("Enter name(16 characters max): ");
	while (1) {
		if (fgets(userName, MAX_NAME_LEN, stdin)) {
			size_t len = strlen(userName);
			if (len > 0 && userName[len - 1] == '\n')
				userName[len - 1] = '\0'; // Убираем \n

			if (strlen(userName) <= 16) {
				// Add prefix [NAME]
				char prefix[] = "[NAME]";
				size_t len_prefix = strlen(prefix);
				len = strlen(userName);

				memmove(userName + len_prefix, userName, len + 1);
				memcpy(userName, prefix, len_prefix);
				break;
			}
			else printf("Failed to get name. Try again: \n");
		}
	}

	// Send the name to server
	if (send(ConnectSocket, userName, (int)strlen(userName), 0) == SOCKET_ERROR)
		printf("send failed: %d\n", WSAGetLastError());

	Sleep(100); // Little delay so server can process the name

	printf("\nConnected to server. Type messages to send. Type 'exit' to quit.\n");

	// Create threads for sending and receiving messages
	threads[SEND_THREAD] = CreateThread(
		NULL,
		0,
		ClientSendMessage,
		(LPVOID)ConnectSocket,
		0,
		NULL
	);

	threads[RECV_THREAD] = CreateThread(
		NULL,
		0,
		ClientRecieveMessage,
		(LPVOID)ConnectSocket,
		0,
		NULL
	);

	// cleanup
	WaitForMultipleObjects(THREAD_COUNT, threads, TRUE, INFINITE);

	for (int i = 0; i < THREAD_COUNT; i++)
		CloseHandle(threads[i]);

	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}