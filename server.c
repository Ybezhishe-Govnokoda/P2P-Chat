#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_PORT "27015"
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 50
#define MAX_NAME_LEN 32
#define CODE_LENGTH 6

typedef struct {
   SOCKET socket;
   char name[MAX_NAME_LEN];
} Client;

Client clients[MAX_CLIENTS];
int clientCount = 0;
CRITICAL_SECTION clientsLock; // To protect access to clients array

DWORD __stdcall ClientHandler(LPVOID lpParam) {
   SOCKET clientSocket = (SOCKET)(uintptr_t)lpParam;
   char recvbuf[BUFFER_SIZE];
   int bytesReceived;
   char senderName[MAX_NAME_LEN] = "Unknown";

   while ((bytesReceived = recv(clientSocket, recvbuf, BUFFER_SIZE, 0)) > 0) {
      // Note: bytesReceived may be 0..BUFFER_SIZE. We do not assume NUL-terminated.
      // For string operations below we temporarily NUL-terminate a copy if needed.

      // Handle NAME command (text based) — safe to treat as string since clients send it as text
      if (bytesReceived >= CODE_LENGTH &&
         strncmp(recvbuf, "[NAME]", CODE_LENGTH) == 0) {
         // It's a name set request (we can NUL-terminate safely for parsing)
         // Create a temporary null-terminated string to extract the name
         char tmp[BUFFER_SIZE + 1];
         int copy_len = bytesReceived < BUFFER_SIZE ? bytesReceived : BUFFER_SIZE - 1;
         memcpy(tmp, recvbuf, copy_len);
         tmp[copy_len] = '\0';

         EnterCriticalSection(&clientsLock);
         for (int i = 0; i < clientCount; i++) {
            if (clients[i].socket == clientSocket) {
               // copy name after the tag "[NAME]"
               strncpy_s(clients[i].name, MAX_NAME_LEN, tmp + 6, _TRUNCATE);
               clients[i].name[MAX_NAME_LEN - 1] = '\0';
               strncpy_s(senderName, MAX_NAME_LEN, clients[i].name, _TRUNCATE);
               senderName[MAX_NAME_LEN - 1] = '\0';
               printf("Client set name: %s\n", clients[i].name);
               break;
            }
         }
         LeaveCriticalSection(&clientsLock);
         continue;
      }

      // For logging: attempt to detect whether this is a group key or group message marker
      // Do a safe check on the beginning of buffer (since buffer may not be NUL-terminated)
      if (bytesReceived >= 6) {
         if (strncmp(recvbuf, "[GKEY]", 6) == 0) {
            printf("[%s] sent group key (forwarding)...\n", senderName);
         }
         else if (strncmp(recvbuf, "[GMSG]", 6) == 0) {
            printf("[%s] sent group message (forwarding)...\n", senderName);
         }
         else {
            // generic encrypted/unknown payload
            printf("[%s] sent data (len=%d) — forwarding...\n", senderName, bytesReceived);
         }
      }
      else {
         printf("[%s] sent data (len=%d) — forwarding...\n", senderName, bytesReceived);
      }

      // Broadcast raw bytesReceived to other clients
      EnterCriticalSection(&clientsLock);
      for (int i = 0; i < clientCount; i++) {
         SOCKET dst = clients[i].socket;
         if (dst != clientSocket && dst != INVALID_SOCKET) {
            int total_sent = 0;
            while (total_sent < bytesReceived) {
               int s = send(dst, recvbuf + total_sent, bytesReceived - total_sent, 0);
               if (s == SOCKET_ERROR) {
                  int err = WSAGetLastError();
                  printf("send() to client %d failed: %d\n", i, err);
                  break;
               }
               total_sent += s;
            }
         }
      }
      LeaveCriticalSection(&clientsLock);
   }

   if (bytesReceived == 0) {
      // connection closed gracefully
      printf("Client disconnected (socket %llu)\n", (unsigned long long)clientSocket);
   }
   else if (bytesReceived == SOCKET_ERROR) {
      printf("recv failed: %d\n", WSAGetLastError());
   }

   // If disconnected - delete from clients array
   EnterCriticalSection(&clientsLock);
   for (int i = 0; i < clientCount; i++) {
      if (clients[i].socket == clientSocket) {
         printf("Removing client '%s' (socket %llu)\n", clients[i].name, (unsigned long long)clientSocket);
         // swap-with-last
         clients[i] = clients[clientCount - 1];
         clientCount--;
         break;
      }
   }
   LeaveCriticalSection(&clientsLock);

   closesocket(clientSocket);
   return 0;
}

int __cdecl main(void) {
   WSADATA wsaData;

   SOCKET ServerSocket = INVALID_SOCKET, ClientSocket = INVALID_SOCKET;
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

   // Main accept loop
   while (1) {
      ClientSocket = accept(ServerSocket, NULL, NULL);
      if (ClientSocket == INVALID_SOCKET) {
         printf("accept() failed: %d\n", WSAGetLastError());
         continue;
      }

      EnterCriticalSection(&clientsLock);
      if (clientCount < MAX_CLIENTS) {
         clients[clientCount].socket = ClientSocket;
         clients[clientCount].name[0] = '\0';
         // create thread for new client
         DWORD tid;
         threads[clientCount] = CreateThread(
            NULL,
            0,
            ClientHandler,
            (LPVOID)ClientSocket,
            0,
            &tid
         );
         if (!threads[clientCount]) {
            printf("CreateThread failed: %d\n", GetLastError());
            // cleanup slot
            clients[clientCount].socket = INVALID_SOCKET;
         }
         else {
            clientCount++;
            printf("Client connected! Total: %d\n", clientCount);
         }
         LeaveCriticalSection(&clientsLock);
      }
      else {
         LeaveCriticalSection(&clientsLock);
         printf("Server full, closing new connection.\n");
         closesocket(ClientSocket);
      }
   }

   // never reached in this simple server, but for completeness:
   for (int i = 0; i < clientCount; i++) {
      CloseHandle(threads[i]);
      shutdown(clients[i].socket, SD_BOTH);
      closesocket(clients[i].socket);
   }

   closesocket(ServerSocket);
   WSACleanup();
   DeleteCriticalSection(&clientsLock);
   return 0;
}