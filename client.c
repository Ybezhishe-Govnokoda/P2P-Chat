#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#include "openssl\applink.c"
#include "msg_encryption.h"


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

#define IV_LEN 12
#define TAG_LEN 16


typedef enum {
	SUCCESS = 0,
	GENERATE_KEY_FAIL = -1,
	BASE64_ENCODE_FAIL = -2,
	SEND_FAIL = -3,
} client_state;


// Enable Virtual Terminal Processing for colored output
#define EnableVTMode() do {                         \
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);   \
	if (hOut == INVALID_HANDLE_VALUE) return;        \
                                                    \
	DWORD dwMode = 0;                                \
	if (!GetConsoleMode(hOut, &dwMode)) return;      \
                                                    \
	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;    \
	SetConsoleMode(hOut, dwMode);                    \
} while (0);


// -----------------------------------------
// GENERATE SENDER KEY (Group Key)
// -----------------------------------------
int generate_group_key(unsigned char *group_key_out) {
	if (RAND_bytes(group_key_out, SENDER_KEY_LEN) != 1) {
		fprintf(stderr, "RAND_bytes failed generating group key\n");
		return GENERATE_KEY_FAIL;
	}
	return SUCCESS;
}

// -----------------------------------------
// Encode and send group key to server
// -----------------------------------------
int send_group_key(SOCKET sock, const unsigned char *group_key) {
	// Base64 encode the AES key
	char *b64 = base64_encode(group_key, SENDER_KEY_LEN);
	if (!b64) {
		fprintf(stderr, "base64 encode group key failed\n");
		return BASE64_ENCODE_FAIL;
	}

	// Format packet: [GKEY][base64_key]
	char msg[256];
	snprintf(msg, sizeof(msg), "[GKEY][%s]", b64);

	free(b64);

	if (send(sock, msg, (int)strlen(msg), 0) <= 0) {
		fprintf(stderr, "send group key failed\n");
		return SEND_FAIL;
	}

	return SUCCESS;
}


// ---------- client send thread ----------
DWORD __stdcall ClientSendMessage(LPVOID lpParam) {
	SOCKET sock = (SOCKET)(uintptr_t)lpParam;
	char buffer[BUFFER_SIZE];

	unsigned char iv[IV_LEN];
	unsigned char tag[TAG_LEN];

	while (1) {

		// Read input from user
		if (!fgets(buffer, sizeof(buffer), stdin))
			break;

		// Remove trailing newline
		size_t plain_len = strlen(buffer);
		if (plain_len > 0 && buffer[plain_len - 1] == '\n') {
			buffer[plain_len - 1] = '\0';
			plain_len--;
		}

		// Check for exit command
		if (strcmp(buffer, "exit") == 0) {
			shutdown(sock, SD_SEND);
			break;
		}


		if (!group_key_set) {
			printf("Cannot send: group key not received yet.\n");
			continue;
		}

		// Make IV
		if (RAND_bytes(iv, IV_LEN) != 1) {
			fprintf(stderr, "RAND_bytes(iv) failed\n");
			break;
		}

		// Encrypt message in-place
		int ciphertext_len =
			aes256_gcm_encrypt(
				(unsigned char *)buffer,
				(int)plain_len,
				group_key,
				iv, tag);

		if (ciphertext_len < 0) {
			fprintf(stderr, "AES-GCM encrypt failed\n");
			break;
		}

		// Base64 encode parts
		char *b64_iv = base64_encode(iv, IV_LEN);
		char *b64_tag = base64_encode(tag, TAG_LEN);
		char *b64_ct = base64_encode((unsigned char *)buffer, ciphertext_len);

		if (!b64_iv || !b64_tag || !b64_ct) {
			fprintf(stderr, "base64 encode failed\n");
			free(b64_iv); free(b64_tag); free(b64_ct);
			break;
		}

		// Final message: [GMSG][iv][tag][ciphertext]
		char final_msg[BUFFER_SIZE * 2];
		snprintf(final_msg, sizeof(final_msg),
			"[GMSG][%s][%s][%s]", b64_iv, b64_tag, b64_ct);

		free(b64_iv);
		free(b64_tag);
		free(b64_ct);

		// Send it
		if (send(sock, final_msg, (int)strlen(final_msg), 0) == SOCKET_ERROR) {
			fprintf(stderr, "send() failed: %d\n", WSAGetLastError());
			break;
		}
	}

	shutdown(sock, SD_SEND);
	return 0;
}


DWORD __stdcall ClientRecieveMessage(LPVOID lpParam) {
	SOCKET sock = (SOCKET)lpParam;
	char buf[BUFFER_SIZE];

	while (1) {

		int r = recv(sock, buf, BUFFER_SIZE - 1, 0);
		if (r <= 0) {
			printf("\nServer closed connection\n");
			return 1;
		}

		buf[r] = '\0';

		// Is it group key?
		if (strncmp(buf, "[GKEY]", 6) == 0) {

			char *p = strchr(buf + 6, '[');
			if (!p) continue;

			char *b64 = p + 1;
			char *end = strchr(b64, ']');
			if (!end) continue;

			*end = '\0';

			unsigned char *bin = NULL;
			int bin_len = base64_decode(b64, strlen(b64), &bin);
			if (bin_len == SENDER_KEY_LEN) {
				memcpy(group_key, bin, SENDER_KEY_LEN);
				group_key_set = 1;
				printf("Group key received!\n");
			}

			free(bin);
			continue;
		}

		// Is it encrypted group message?
		if (strncmp(buf, "[GMSG]", 6) == 0) {

			char *p = buf + 6;

			// [iv]
			char *b64_iv = strchr(p, '[') + 1;
			char *end_iv = strchr(b64_iv, ']');
			*end_iv = 0;

			// [tag]
			char *b64_tag = strchr(end_iv + 1, '[') + 1;
			char *end_tag = strchr(b64_tag, ']');
			*end_tag = 0;

			// [cipher]
			char *b64_ct = strchr(end_tag + 1, '[') + 1;
			char *end_ct = strchr(b64_ct, ']');
			*end_ct = 0;

			unsigned char *iv_bin = NULL;
			unsigned char *tag_bin = NULL;
			unsigned char *cipher_text_bin = NULL;

			int iv_len = base64_decode(b64_iv, strlen(b64_iv), &iv_bin);
			int tag_len = base64_decode(b64_tag, strlen(b64_tag), &tag_bin);
			int ct_len = base64_decode(b64_ct, strlen(b64_ct), &cipher_text_bin);

			if (iv_len != IV_LEN || tag_len != TAG_LEN) {
				free(iv_bin); free(tag_bin); free(cipher_text_bin);
				continue;
			}

			int plain_text_len = aes256_gcm_decrypt(
				cipher_text_bin, ct_len, 
				group_key, iv_bin, tag_bin);

			if (plain_text_len >= 0) {
				cipher_text_bin[plain_text_len] = '\0';
				printf("%s\n", cipher_text_bin);
			}

			free(iv_bin); free(tag_bin); free(cipher_text_bin);
			continue;
		}

		// Fallback: plain message
		printf("%s\n", buf);
	}

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


	EnableVTMode()

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

	if (generate_group_key(group_key) != SUCCESS) {
		printf("Failed to generate group key\n");
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	if (send_group_key(ConnectSocket, group_key) != SUCCESS) {
		printf("Failed to send group key to server\n");
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}
	group_key_set = 1;
	printf("Local group key generated and sent;\n");

	printf("Enter name(16 characters max): ");
	while (1) {
		if (fgets(userName, MAX_NAME_LEN, stdin)) {
			size_t len = strlen(userName);
			if (len > 0 && userName[len - 1] == '\n')
				userName[len - 1] = '\0'; // Remove \n

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

	Sleep(300); // Little delay so server can process the name

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