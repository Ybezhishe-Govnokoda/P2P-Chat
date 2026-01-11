#pragma once

// ========================
// SERVER SIDE DEFINITIONS
// ========================
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

// Socket macros
typedef SOCKET my_socket_t;
#define my_close(s) closesocket(s)

// Threading macros
#define THREAD_TYPE HANDLE
#define THREAD_CREATE(thr, func, param) thr = CreateThread(NULL, 0, func, param, 0, NULL)
#define THREAD_JOIN(thr) WaitForSingleObject(thr, INFINITE)
#define MUTEX_TYPE CRITICAL_SECTION
#define MUTEX_INIT(m) InitializeCriticalSection(&m)
#define MUTEX_LOCK(m) EnterCriticalSection(&m)
#define MUTEX_UNLOCK(m) LeaveCriticalSection(&m)
#define MUTEX_DESTROY(m) DeleteCriticalSection(&m)

// Winsock macros (Windows only)
#define INIT_WINSOCK() do { \
   WSADATA wsaData; \
   if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) { \
      printf("WSAStartup failed.\n"); \
      return 1; \
   } \
} while (0)

#define WSA_CLEANUP() WSACleanup()

#else // Linux / POSIX

#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

// Socket macros
typedef int my_socket_t;
#define my_close(s) close(s)

// Threading macros
#define THREAD_TYPE pthread_t
#define THREAD_CREATE(thr, func, param) pthread_create(&thr, NULL, func, param)
#define THREAD_JOIN(thr) pthread_join(thr, NULL)
#define MUTEX_TYPE pthread_mutex_t
#define MUTEX_INIT(m) pthread_mutex_init(&m, NULL)
#define MUTEX_LOCK(m) pthread_mutex_lock(&m)
#define MUTEX_UNLOCK(m) pthread_mutex_unlock(&m)
#define MUTEX_DESTROY(m) pthread_mutex_destroy(&m)

// Winsock macros (Windows only)
#define INIT_WINSOCK() ((void)0)
#define WSA_CLEANUP() ((void)0)

#endif // _WIN32

#define DEFAULT_PORT "27015"
#define SERVER_BUFFER_SIZE 4096
#define MAX_CLIENTS 50
#define MAX_NAME_LEN 16
#define CODE_LENGTH 6

typedef struct {
   my_socket_t socket;
   char name[MAX_NAME_LEN];
} Client;

#ifdef _WIN32
#define ClientHandler(lpParam) DWORD __stdcall ClientHandler(void *lpParam)
#define R_NULL 0 // For returning 0 in Windows and void* in Linux
#else
#define ClientHandler(lpParam) void *ClientHandler(void *lpParam)
#define R_NULL NULL
#endif


// =======================
// CLIENT SIDE DEFINITIONS
// =======================
#ifdef _WIN32

#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")

#define my_shutdown_send(s) shutdown(s, SD_SEND)
#define my_get_last_error() WSAGetLastError()
#define MY_SEND_ERROR SOCKET_ERROR

#define THREAD_SLEEP(ms) Sleep(ms)

// Enable VT processing for colors (Windows only)
#define EnableVTMode() do {                         \
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);   \
        if (hOut == INVALID_HANDLE_VALUE) break;        \
        DWORD dwMode = 0;                                \
        if (!GetConsoleMode(hOut, &dwMode)) break;      \
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;    \
        SetConsoleMode(hOut, dwMode);                    \
    } while(0)

#else // Linux / POSIX

#define my_shutdown_send(s) shutdown(s, SHUT_WR)
#define my_get_last_error() errno
#define MY_SEND_ERROR -1

#define THREAD_SLEEP(ms) usleep((ms)*1000)

// VT colors needed in Linux
#define EnableVTMode() ((void)0)

#endif // _WIN32

#define CLIENT_BUFFER_SIZE 1024
#define THREAD_COUNT 2
#define SEND_THREAD 0
#define RECV_THREAD 1

#define IV_LEN 12
#define TAG_LEN 16

#define IP_LENGTH 15

typedef enum {
   SUCCESS = 0,
   GENERATE_KEY_FAIL = -1,
   BASE64_ENCODE_FAIL = -2,
   SEND_FAIL = -3,
} client_state;

#ifdef _WIN32
#define ClientSendMessage(client) DWORD __stdcall ClientSendMessage(Client *client)
#else
#define ClientSendMessage(client) void *ClientSendMessage(Client *client)
#endif

#ifdef _WIN32
#define ClientRecieveMessage(lpParam) DWORD __stdcall ClientRecieveMessage(LPVOID lpParam)
#else
#define ClientRecieveMessage(lpParam) void __stdcall *ClientRecieveMessage(void lpParam)
#endif