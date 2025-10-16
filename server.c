#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/applink.c>

#include "msg_parser.h"
#include "msg_encryption.h"


// Necessary for linking with ws2_32.lib
#pragma comment(lib, "ws2_32.lib")


#define DEFAULT_PORT "27015"
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 50
#define MAX_NAME_LEN 32
#define CODE_LENGTH 6

#define CLEANUP \
do {\
   if (enc_key_bin) free(enc_key_bin);\
   if (iv_bin) free(iv_bin);\
   if (tag_bin) free(tag_bin);\
   if (ct_bin) free(ct_bin);\
} while (0);


typedef struct {
    SOCKET socket;
	 char name[MAX_NAME_LEN];
} Client;


Client clients[MAX_CLIENTS];
int clientCount = 0;
CRITICAL_SECTION clientsLock; // To protect access to clients array
EVP_PKEY *g_server_privkey = NULL;


DWORD __stdcall ClientHandler(LPVOID lpParam) {
   SOCKET clientSocket = (SOCKET)(uintptr_t)lpParam;
   char recvbuf[BUFFER_SIZE];
   int bytesReceived;
   char senderName[MAX_NAME_LEN] = "Unknown";

   while ((bytesReceived = recv(clientSocket, recvbuf, BUFFER_SIZE - 1, 0)) > 0) {
      recvbuf[bytesReceived] = '\0';

		// Check for name setting message
      if (strncmp(recvbuf, "[NAME]", CODE_LENGTH) == 0) {
         EnterCriticalSection(&clientsLock);
         for (int i = 0; i < clientCount; i++) {
            if (clients[i].socket == clientSocket) {
               strncpy_s(clients[i].name, MAX_NAME_LEN, recvbuf + 6, MAX_NAME_LEN - 1);
               clients[i].name[MAX_NAME_LEN - 1] = '\0';
               strncpy_s(senderName, MAX_NAME_LEN, clients[i].name, MAX_NAME_LEN);
               printf("Client set name: %s\n", clients[i].name);
               break;
            }
         }
         LeaveCriticalSection(&clientsLock);
         continue;
      }

      // parse -> get binary fields (malloced)
      int enc_key_len = 0;
      unsigned char *enc_key_bin = NULL, *iv_bin = NULL, *tag_bin = NULL, *ct_bin = NULL;
      int enc_key_bin_len = 0, iv_len = 0, tag_len = 0, ct_len = 0;

      if (parse_message_base64(recvbuf,
         &enc_key_len,
         &enc_key_bin, &enc_key_bin_len,
         &iv_bin, &iv_len,
         &tag_bin, &tag_len,
         &ct_bin, &ct_len) != PARSE_OK) {

         printf("Failed to parse message from client.\n");
         // free if any allocated
         CLEANUP;
         continue;
      }

      unsigned char *aes_key = AES_key_decrypt(
         g_server_privkey, 
         enc_key_bin, 
         enc_key_bin_len
      );
      if (!aes_key) {
         printf("Failed to decrypt AES key.\n");
         CLEANUP;
         continue;
      }

      // Decrypt ciphertext (in-place)
      int pt_len = aes_gcm_decrypt_inplace(
         ct_bin, ct_len, 
         aes_key, iv_bin, 
         iv_len, tag_bin
      );
      if (pt_len < 0) {
         printf("AES-GCM decryption failed (auth fail)\n");
         CLEANUP;
      }

      // Ensure null-termination for text usage
      int printable_len = pt_len;
      if (printable_len >= BUFFER_SIZE - 1) printable_len = BUFFER_SIZE - 2;
      ct_bin[printable_len] = '\0';

      printf("[%s]: %s\n", senderName, (char *)ct_bin);

      // Broadcast plaintext to other clients
      char messageWithName[BUFFER_SIZE + MAX_NAME_LEN + 8];
      snprintf(
         messageWithName, sizeof(messageWithName), 
         "\x1B[32m%s:\033[0m %s", 
         senderName, 
         (char *)ct_bin
      );

      EnterCriticalSection(&clientsLock);
      for (int i = 0; i < clientCount; i++) {
         if (clients[i].socket != clientSocket) {
            int sent = send(clients[i].socket, messageWithName, (int)strlen(messageWithName), 0);
            if (sent == SOCKET_ERROR) {
               printf("send() failed: %d\n", WSAGetLastError());
            }
         }
      }
      LeaveCriticalSection(&clientsLock);

      CLEANUP;
   }

	// If disconnected - delete from clients array
   EnterCriticalSection(&clientsLock);
   for (int i = 0; i < clientCount; i++) {
      if (clients[i].socket == clientSocket) {
         printf("Client %s disconnected\n", clients[i].name);
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

   g_server_privkey = load_private_key("server_priv.pem");
   if (!g_server_privkey) return 1;

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
         clients[clientCount++].socket = ClientSocket;
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
   return 0;
}