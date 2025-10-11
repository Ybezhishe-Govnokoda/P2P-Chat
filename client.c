#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "openssl\applink.c"


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

#define AES_KEY_LEN 16
#define IV_LEN 12
#define TAG_LEN 16


// Enable Virtual Terminal Processing for colored output
inline void EnableVTMode() {
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hOut == INVALID_HANDLE_VALUE) return;

	DWORD dwMode = 0;
	if (!GetConsoleMode(hOut, &dwMode)) return;

	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode(hOut, dwMode);
}

// ---------- utility: base64 encode ----------
char *base64_encode(const unsigned char *input, int length) {
	BIO *bmem = NULL, *b64 = NULL;
	BUF_MEM *bptr;
	char *buff = NULL;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // no newlines
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);

	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	buff = (char *)malloc(bptr->length + 1);
	if (!buff) { BIO_free_all(b64); return NULL; }
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = '\0';

	BIO_free_all(b64);
	return buff; // caller must free
}

// ---------- load public key as EVP_PKEY ----------
EVP_PKEY *load_public_key_evp(const char *filename) {
	FILE *fp = fopen(filename, "rb");
	if (!fp) { perror("open pubkey"); return NULL; }
	EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);
	return pkey;
}

// ---------- AES-GCM encrypt in-place (EVP). Returns ciphertext_len or -1 on error ----------
int aes_gcm_encrypt_inplace(unsigned char *buffer, int buf_len,
	const unsigned char *key,
	const unsigned char *iv, int iv_len,
	unsigned char *tag_out)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0, outlen = 0;
	int ret = -1;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;

	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) goto done;
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto done;
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;

	if (1 != EVP_EncryptUpdate(ctx, buffer, &len, buffer, buf_len)) goto done;
	outlen = len;

	if (1 != EVP_EncryptFinal_ex(ctx, buffer + len, &len)) goto done;
	outlen += len;

	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag_out)) goto done;

	ret = outlen;

done:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

// ---------- client send thread ----------
DWORD __stdcall ClientSendMessage(LPVOID lpParam) {
	SOCKET connectSocket = (SOCKET)(uintptr_t)lpParam;
	char buffer[BUFFER_SIZE];
	unsigned char aes_key[AES_KEY_LEN];
	unsigned char iv[IV_LEN];
	unsigned char tag[TAG_LEN];

	while (1) {
		// Read line
		if (!fgets(buffer, sizeof(buffer), stdin)) break;
		size_t plain_len = strlen(buffer);
		if (plain_len > 0 && buffer[plain_len - 1] == '\n') { 
			buffer[plain_len - 1] = '\0'; 
			plain_len--; 
		}

		if (plain_len == 0) continue;
		if (strcmp(buffer, "exit") == 0) {
			shutdown(connectSocket, SD_SEND);
			break;
		}

		// Generate AES key + IV
		if (RAND_bytes(aes_key, sizeof(aes_key)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
			fprintf(stderr, "RAND_bytes failed\n");
			break;
		}

		// Copy plaintext into a binary buffer for in-place encryption
		// Use a buffer large enough: ciphertext_len == plain_len for GCM
		unsigned char *ciphertext_buf = (unsigned char *)malloc(plain_len + 1); // +1 for safety when null-terminating later
		if (!ciphertext_buf) { 
			fprintf(stderr, "malloc failed\n"); 
			break; 
		}
		memcpy(ciphertext_buf, buffer, plain_len);

		int ciphertext_len = aes_gcm_encrypt_inplace(ciphertext_buf, (int)plain_len, aes_key, iv, IV_LEN, tag);
		if (ciphertext_len < 0) {
			fprintf(stderr, "AES-GCM encrypt failed\n");
			free(ciphertext_buf);
			break;
		}

		// Load server public key (EVP)
		EVP_PKEY *pub = load_public_key_evp("server_pub.pem");
		if (!pub) { 
			fprintf(stderr, "load_public_key_evp failed\n"); 
			free(ciphertext_buf); 
			break; 
		}

		// Encrypt AES key with server public key (EVP_PKEY_encrypt)
		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pub, NULL);
		if (!pctx) { 
			fprintf(stderr, "EVP_PKEY_CTX_new failed\n"); 
			EVP_PKEY_free(pub); 
			free(ciphertext_buf);
			break; 
		}
		// Initialize for encryption
		if (EVP_PKEY_encrypt_init(pctx) <= 0) { 
			fprintf(stderr, "encrypt_init failed\n"); 
			EVP_PKEY_CTX_free(pctx); 
			EVP_PKEY_free(pub); 
			free(ciphertext_buf); 
			break; 
		}
		// set RSA OAEP padding
		if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0) { 
			fprintf(stderr, "set padding failed\n"); 
			EVP_PKEY_CTX_free(pctx); 
			EVP_PKEY_free(pub); 
			free(ciphertext_buf);
			break; 
		}

		// First call to get required size
		size_t enc_key_len = 0;
		if (EVP_PKEY_encrypt(pctx, NULL, &enc_key_len, aes_key, sizeof(aes_key)) <= 0) { 
			fprintf(stderr, "get outlen failed\n"); 
			EVP_PKEY_CTX_free(pctx); 
			EVP_PKEY_free(pub); 
			free(ciphertext_buf);
			break; 
		}

		unsigned char *enc_key = malloc(enc_key_len);
		if (!enc_key) { 
			fprintf(stderr, "malloc enc_key failed\n"); 
			EVP_PKEY_CTX_free(pctx); 
			EVP_PKEY_free(pub); 
			free(ciphertext_buf); 
			break; 
		}
		if (EVP_PKEY_encrypt(pctx, enc_key, &enc_key_len, aes_key, sizeof(aes_key)) <= 0) {
			fprintf(stderr, "EVP_PKEY_encrypt failed\n"); 
			EVP_PKEY_CTX_free(pctx); 
			EVP_PKEY_free(pub); 
			free(enc_key); 
			free(ciphertext_buf); 
			break;
		}
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_free(pub);

		// Base64-encode binary parts: enc_key, iv, tag, ciphertext
		char *b64_enc_key = base64_encode(enc_key, (int)enc_key_len);
		char *b64_iv = base64_encode(iv, IV_LEN);
		char *b64_tag = base64_encode(tag, TAG_LEN);
		char *b64_ct = base64_encode(ciphertext_buf, ciphertext_len);

		if (!b64_enc_key || !b64_iv || !b64_tag || !b64_ct) {
			fprintf(stderr, "base64 encode failed\n");
			free(enc_key); free(ciphertext_buf);
			if (b64_enc_key) free(b64_enc_key);
			if (b64_iv) free(b64_iv);
			if (b64_tag) free(b64_tag);
			if (b64_ct) free(b64_ct);
			break;
		}

		// Format the message: [<enc_key_len>][<enc_key_b64>][<iv_b64>][<tag_b64>][<ciphertext_b64>]
		// enc_key_len is the raw encrypted key length in bytes (not base64 length)
		char *final_msg = (char *)malloc(6 + strlen(b64_enc_key) + strlen(b64_iv) + strlen(b64_tag) + strlen(b64_ct) + 64);
		if (!final_msg) { 
			fprintf(stderr, "malloc final_msg failed\n"); 
			free(enc_key); free(ciphertext_buf); 
			free(b64_enc_key); free(b64_iv); 
			free(b64_tag); free(b64_ct); 
			break; 
		}

		snprintf(final_msg,
			// safe size  
			6 + strlen(b64_enc_key) + strlen(b64_iv) + strlen(b64_tag) + strlen(b64_ct) + 64,
			"[%zu][%s][%s][%s][%s]", enc_key_len, b64_enc_key, b64_iv, b64_tag, b64_ct);

		// Send
		int send_res = send(connectSocket, final_msg, (int)strlen(final_msg), 0);
		if (send_res == SOCKET_ERROR) {
			fprintf(stderr, "send failed: %d\n", WSAGetLastError());
		}

		// Cleanup
		free(enc_key);
		free(ciphertext_buf);
		free(b64_enc_key);
		free(b64_iv);
		free(b64_tag);
		free(b64_ct);
		free(final_msg);
	}

	shutdown(connectSocket, SD_SEND);
	return 0;
}

DWORD __stdcall ClientRecieveMessage(LPVOID lpParam) {
	SOCKET connectSocket = (SOCKET)lpParam;
	char receiveBuffer[BUFFER_SIZE];

	while (1) {
		int iResult = recv(connectSocket, receiveBuffer, BUFFER_SIZE - 1, 0);
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
	shutdown(connectSocket, SD_RECEIVE);
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