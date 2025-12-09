#include "server.h"

// Global clients array and lock
Client clients[MAX_CLIENTS];
int clientCount = 0;
MUTEX_TYPE clientsLock;


#ifdef _WIN32
DWORD __stdcall ClientHandler(void *lpParam) {
#else
void __stdcall *ClientHandler(void *lpParam) {
#endif
   my_socket_t clientSocket = (my_socket_t)(uintptr_t)lpParam;
   char recvbuf[BUFFER_SIZE];
   int bytesReceived;
   char senderName[MAX_NAME_LEN] = "Unknown";

   while ((bytesReceived = recv(clientSocket, recvbuf, BUFFER_SIZE, 0)

      ) > 0)
   {
      // Handling [NAME], [GKEY], [GMSG]
      if (bytesReceived >= CODE_LENGTH && strncmp(recvbuf, "[NAME]", CODE_LENGTH) == 0) {
         char tmp[BUFFER_SIZE + 1];
         int copy_len = bytesReceived < BUFFER_SIZE ? bytesReceived : BUFFER_SIZE - 1;
         memcpy(tmp, recvbuf, copy_len);
         tmp[copy_len] = '\0';

         MUTEX_LOCK(clientsLock);
         for (int i = 0; i < clientCount; i++) {
            if (clients[i].socket == clientSocket) {
               strncpy(clients[i].name, tmp + 6, MAX_NAME_LEN - 1);
               clients[i].name[MAX_NAME_LEN - 1] = '\0';
               strncpy(senderName, clients[i].name, MAX_NAME_LEN - 1);
               senderName[MAX_NAME_LEN - 1] = '\0';
               printf("Client set name: %s\n", clients[i].name);
               break;
            }
         }
         MUTEX_UNLOCK(clientsLock);
         continue;
      }

      // Broadcast
      MUTEX_LOCK(clientsLock);
      for (int i = 0; i < clientCount; i++) {
         my_socket_t dst = clients[i].socket;
         if (dst != clientSocket) {
            int total_sent = 0;
            while (total_sent < bytesReceived) {
               int s = send(dst, recvbuf + total_sent, bytesReceived - total_sent, 0);
               if (s < 0) break;
               total_sent += s;
            }
         }
      }
      MUTEX_UNLOCK(clientsLock);
   }

   // Remove client
   MUTEX_LOCK(clientsLock);
   for (int i = 0; i < clientCount; i++) {
      if (clients[i].socket == clientSocket) {
         clients[i] = clients[clientCount - 1];
         clientCount--;
         break;
      }
   }
   MUTEX_UNLOCK(clientsLock);

   my_close(clientSocket);

#ifndef _WIN32
   return NULL;
#else
   return 0;
#endif
}


int main(void) {
   my_socket_t ServerSocket = -1, ClientSocket = -1;
   struct addrinfo *result = NULL, hints;
   THREAD_TYPE threads[MAX_CLIENTS];

#ifdef _WIN32
   WSADATA wsaData;
   if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
      printf("WSAStartup failed.\n");
      return 1;
   }
#endif

   MUTEX_INIT(clientsLock);

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_INET;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_protocol = IPPROTO_TCP;
   hints.ai_flags = AI_PASSIVE;

   if (getaddrinfo(NULL, DEFAULT_PORT, &hints, &result) != 0) {
      perror("getaddrinfo failed");
#ifdef _WIN32
      WSACleanup();
#endif
      return 1;
   }

   ServerSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
   if (ServerSocket < 0) {
      perror("socket failed");
      freeaddrinfo(result);
#ifdef _WIN32
      WSACleanup();
#endif
      return 1;
   }

   int opt = 1;
   setsockopt(ServerSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

   if (bind(ServerSocket, result->ai_addr, (int)result->ai_addrlen) < 0) {
      perror("bind failed");
      freeaddrinfo(result);
      my_close(ServerSocket);
#ifdef _WIN32
      WSACleanup();
#endif
      return 1;
   }

   freeaddrinfo(result);

   if (listen(ServerSocket, SOMAXCONN) < 0) {
      perror("listen failed");
      my_close(ServerSocket);
#ifdef _WIN32
      WSACleanup();
#endif
      return 1;
   }

   printf("Server is listening on port %s...\n", DEFAULT_PORT);

   while (1) {
      ClientSocket = accept(ServerSocket, NULL, NULL);
      if (ClientSocket < 0) {
         perror("accept failed");
         continue;
      }

      MUTEX_LOCK(clientsLock);
      if (clientCount < MAX_CLIENTS) {
         clients[clientCount].socket = ClientSocket;
         clients[clientCount].name[0] = '\0';

         THREAD_CREATE(threads[clientCount], ClientHandler, (void *)(uintptr_t)ClientSocket);
         clientCount++;
         printf("Client connected! Total: %d\n", clientCount);
      }
      else {
         printf("Server full, closing new connection.\n");
         my_close(ClientSocket);
      }
      MUTEX_UNLOCK(clientsLock);
   }

   // Cleanup (never reached normally)
   for (int i = 0; i < clientCount; i++) {
      THREAD_JOIN(threads[i]);
      my_close(clients[i].socket);
   }
   my_close(ServerSocket);
#ifdef _WIN32
   WSACleanup();
#endif
   MUTEX_DESTROY(clientsLock);
   return 0;
}