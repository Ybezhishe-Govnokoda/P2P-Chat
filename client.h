#pragma once

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "msg_encryption.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "openssl/applink.c"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")

typedef SOCKET my_socket_t;
#define my_close(s) closesocket(s)
#define my_shutdown_send(s) shutdown(s, SD_SEND)
#define my_get_last_error() WSAGetLastError()
#define MY_SEND_ERROR SOCKET_ERROR

#define THREAD_TYPE HANDLE
#define THREAD_CREATE(thr, func, param) thr = CreateThread(NULL, 0, func, param, 0, NULL)
#define THREAD_JOIN(thr) WaitForSingleObject(thr, INFINITE)
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
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

typedef int my_socket_t;
#define my_close(s) close(s)
#define my_shutdown_send(s) shutdown(s, SHUT_WR)
#define my_get_last_error() errno
#define MY_SEND_ERROR -1

#define THREAD_TYPE pthread_t
#define THREAD_CREATE(thr, func, param) pthread_create(&thr, NULL, func, param)
#define THREAD_JOIN(thr) pthread_join(thr, NULL)
#define THREAD_SLEEP(ms) usleep((ms)*1000)

// VT colors обычно работают сразу в Linux
#define EnableVTMode() ((void)0)

#endif


#define BUFFER_SIZE 1024
#define DEFAULT_PORT "27015"
#define THREAD_COUNT 2
#define SEND_THREAD 0
#define RECV_THREAD 1
#define MAX_NAME_LEN 32

#define IV_LEN 12
#define TAG_LEN 16


typedef enum {
   SUCCESS = 0,
   GENERATE_KEY_FAIL = -1,
   BASE64_ENCODE_FAIL = -2,
   SEND_FAIL = -3,
} client_state;