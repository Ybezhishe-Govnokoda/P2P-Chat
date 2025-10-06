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


#define DEFAULT_BUFLEN 1024
#define DEFAULT_PORT "27015"

int __cdecl main(int argc, char **argv)
{
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;

	char sendBuffer[DEFAULT_BUFLEN];
	char receiveBuffer[DEFAULT_BUFLEN];
	int iResult;
	int receiveBufferLength = DEFAULT_BUFLEN;

	// Validate the parameters
	if (argc != 2) {
		printf("usage: %s server-name\n", argv[0]);
		return 1;
	}

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);

		if (ConnectSocket == INVALID_SOCKET) {
			printf("Error at socket(): %ld\n", WSAGetLastError());
			freeaddrinfo(result);
			WSACleanup();
			return 1;
		}

		// Connect to server.
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
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

	while (1) {
		printf("Enter message: ");
		if (!fgets(sendBuffer, DEFAULT_BUFLEN, stdin))
			break;

		size_t len = strlen(sendBuffer);
		if (len > 0 && sendBuffer[len - 1] == '\n')
			sendBuffer[len - 1] = '\0';

		if (strcmp(sendBuffer, "exit") == 0)
			break;

		iResult = send(ConnectSocket, sendBuffer, (int)strlen(sendBuffer), 0);
		if (iResult == SOCKET_ERROR) {
			printf("send failed: %d\n", WSAGetLastError());
			break;
		}

		iResult = recv(ConnectSocket, receiveBuffer, receiveBufferLength, 0);
		if (iResult > 0) {
			receiveBuffer[iResult] = '\0';
			printf("Server: %s\n", receiveBuffer);
		}
		else if (iResult == 0) {
			printf("Server closed connection\n");
			break;
		}
		else {
			printf("recv failed: %d\n", WSAGetLastError());
			break;
		}
	}

	// cleanup
	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}