#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

// Necessary for linking with ws2_32.lib
#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_PORT "27015"
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

SOCKET clients[MAX_CLIENTS];
int clientCount = 0;
CRITICAL_SECTION clientsLock; // To protect access to clients array

DWORD __stdcall ClientHandler(LPVOID lpParam) {
    SOCKET clientSocket = (SOCKET)lpParam;
    char buffer[BUFFER_SIZE];
    int bytesReceived = BUFFER_SIZE;

    while ((bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0)) > 0) {
       if (bytesReceived == 0) {
          printf("Client disconnected\n");
          shutdown(clientSocket, SD_BOTH);
          closesocket(clientSocket);
       }
       else if (bytesReceived == SOCKET_ERROR) {
          printf("recv failed: %d\n", WSAGetLastError());
          shutdown(clientSocket, SD_BOTH);
          closesocket(clientSocket);
       }

       buffer[bytesReceived] = '\0';
		 printf("Received: %s\n", buffer);

		 // Broadcast the message to all other clients
       EnterCriticalSection(&clientsLock);
       for (int i = 0; i < clientCount; i++) {
          if (clients[i] != clientSocket) {
             int sent = send(clients[i], buffer, bytesReceived, 0);
             if (sent == SOCKET_ERROR)
                printf("send() failed: %d\n", WSAGetLastError());
          }
       }
       LeaveCriticalSection(&clientsLock);
    }

	 // Remove client from the list
    EnterCriticalSection(&clientsLock);
    for (int i = 0; i < clientCount; i++) {
       if (clients[i] == clientSocket) {
          clients[i] = clients[clientCount - 1];
          clientCount--;
          break;
       }
    }
    LeaveCriticalSection(&clientsLock);

    closesocket(clientSocket);
    return 0;
}


int __cdecl main(void) 
{
   WSADATA wsaData;

   SOCKET ServerSocket = INVALID_SOCKET,
      ClientSocket = INVALID_SOCKET;

   struct addrinfo *result = NULL, hints;

   HANDLE threads[MAX_CLIENTS];

   InitializeCriticalSection(&clientsLock);

   // Initialize Winsock
   if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
      printf("WSAStartup failed.\n");
      return 1;
   }

	// Set up the hints address info structure
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
   hints.ai_flags = AI_PASSIVE;


	// Resolve the server address and port
   if (getaddrinfo(NULL, DEFAULT_PORT, &hints, &result) != 0) {
      printf("getaddrinfo failed.\n");
      WSACleanup();
      return 1;
   }

	// Create a SOCKET for the server to listen for client connections
   ServerSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
   if (ServerSocket == INVALID_SOCKET) {
      printf("Error at socket(): %ld\n", WSAGetLastError());
      freeaddrinfo(result);
      WSACleanup();
      return 1;
   }

   int opt = 1;
   setsockopt(ServerSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

	// Setup the TCP listening socket
   if (bind(ServerSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
      printf("bind failed with error: %d\n", WSAGetLastError());
      freeaddrinfo(result);
      closesocket(ServerSocket);
      WSACleanup();
      return 1;
   }

   freeaddrinfo(result);

	// Start listening for incoming connections
   if (listen(ServerSocket, SOMAXCONN) == SOCKET_ERROR) {
      printf("Listen failed with error: %d\n", WSAGetLastError());
      closesocket(ServerSocket);
      WSACleanup();
      return 1;
   }
	printf("Server is listening on port %s...\n", DEFAULT_PORT);

   // Processing receiving and sending messages 
   // to the server with multithreading
   while (1) {
      ClientSocket = accept(ServerSocket, NULL, NULL);
      if (ClientSocket == INVALID_SOCKET) {
         printf("accept() failed: %d\n", WSAGetLastError());
         continue;
      }

      EnterCriticalSection(&clientsLock);
      if (clientCount < MAX_CLIENTS) {
         clients[clientCount++] = ClientSocket;
         LeaveCriticalSection(&clientsLock);

         threads[clientCount - 1] = CreateThread(
            NULL, 
            0, 
            ClientHandler, 
            (LPVOID)ClientSocket, 
            0, 
            NULL
         );

         printf("Client connected! Total: %d\n", clientCount);
      }
      else {
         LeaveCriticalSection(&clientsLock);
         printf("Server full, closing new connection.\n");
         closesocket(ClientSocket);
      }
   }

   WaitForMultipleObjects(clientCount, threads, TRUE, INFINITE);

   for (int i = 0; i < clientCount; i++)
      CloseHandle(threads[i]);

   closesocket(ServerSocket);
   WSACleanup();
}
