#pragma once

#pragma once
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

typedef SOCKET my_socket_t;
#define my_close(s) closesocket(s)
#define THREAD_TYPE HANDLE
#define THREAD_CREATE(thr, func, param) thr = CreateThread(NULL, 0, func, param, 0, NULL)
#define THREAD_JOIN(thr) WaitForSingleObject(thr, INFINITE)
#define MUTEX_TYPE CRITICAL_SECTION
#define MUTEX_INIT(m) InitializeCriticalSection(&m)
#define MUTEX_LOCK(m) EnterCriticalSection(&m)
#define MUTEX_UNLOCK(m) LeaveCriticalSection(&m)
#define MUTEX_DESTROY(m) DeleteCriticalSection(&m)
#else
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

typedef int my_socket_t;
#define my_close(s) close(s)
#define THREAD_TYPE pthread_t
#define THREAD_CREATE(thr, func, param) pthread_create(&thr, NULL, func, param)
#define THREAD_JOIN(thr) pthread_join(thr, NULL)
#define MUTEX_TYPE pthread_mutex_t
#define MUTEX_INIT(m) pthread_mutex_init(&m, NULL)
#define MUTEX_LOCK(m) pthread_mutex_lock(&m)
#define MUTEX_UNLOCK(m) pthread_mutex_unlock(&m)
#define MUTEX_DESTROY(m) pthread_mutex_destroy(&m)
#endif

#define DEFAULT_PORT "27015"
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 50
#define MAX_NAME_LEN 32
#define CODE_LENGTH 6

typedef struct {
   my_socket_t socket;
   char name[MAX_NAME_LEN];
} Client;

extern Client clients[MAX_CLIENTS];
extern int clientCount;
extern MUTEX_TYPE clientsLock;
