#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include "openssl\applink.c"


// Necessary for linking with ws2_32.lib
#pragma comment(lib, "ws2_32.lib")

//#define DEBUG

#define DEFAULT_PORT "27015"
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 50
#define MAX_NAME_LEN 32
#define CODE_LENGTH 6

// AES parameters
#define AES_KEY_LEN 16

// Error codes for message parsing
#define PARSE_OK 0
#define PARSE_ERR_FORMAT -1
#define PARSE_ERR_NUM -2


typedef struct {
    SOCKET socket;
	 char name[MAX_NAME_LEN];
} Client;


Client clients[MAX_CLIENTS];
int clientCount = 0;
CRITICAL_SECTION clientsLock; // To protect access to clients array
EVP_PKEY *g_server_privkey = NULL;


// AES decryption function
int aes_gcm_decrypt_inplace(unsigned char *buffer, int buf_len,
   const unsigned char *key,
   const unsigned char *iv, int iv_len,
   const unsigned char *tag)
{
   EVP_CIPHER_CTX *ctx = NULL;
   int len = 0;
   int ret = -1;
   int outlen = 0;

   ctx = EVP_CIPHER_CTX_new();
   if (!ctx) return -1;

   if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
      goto cleanup;

   if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
      goto cleanup;

   if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
      goto cleanup;

   /* Decrypt in-place: output buffer == input buffer */
   if (1 != EVP_DecryptUpdate(ctx, buffer, &len, buffer, buf_len))
      goto cleanup;

   outlen = len;

   /* Set expected tag before finalizing */
   if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag))
      goto cleanup;

   /* Final: returns 1 if tag ok, 0 if tag mismatch */
   if (1 != EVP_DecryptFinal_ex(ctx, buffer + len, &len))
      goto cleanup;

   outlen += len;
   ret = outlen;

cleanup:
   EVP_CIPHER_CTX_free(ctx);
   return ret; /* -1 on error, else plaintext length */
}


EVP_PKEY *load_private_key(const char *filename) {
   FILE *fp = fopen(filename, "rb");
   if (!fp) { perror("open privkey"); return NULL; }
   EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
   fclose(fp);
   return pkey;
}

// base64 decode. Возвращает выделенный буфер (нужно free).
// out_len заполняется длиной в байтах.
unsigned char *base64_decode(const char *b64, int b64_len, int *out_len) {
   BIO *b64bio = NULL, *bmem = NULL;
   unsigned char *buffer = NULL;
   int decoded_len = 0;

   b64bio = BIO_new(BIO_f_base64());
   BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL); // без новых строк
   bmem = BIO_new_mem_buf((void *)b64, b64_len);
   bmem = BIO_push(b64bio, bmem);

   // выделим временно: b64_len (приблизительно) достаточно
   buffer = (unsigned char *)malloc(b64_len + 1);
   if (!buffer) { BIO_free_all(bmem); return NULL; }

   decoded_len = BIO_read(bmem, buffer, b64_len);
   if (decoded_len <= 0) { free(buffer); BIO_free_all(bmem); return NULL; }

   *out_len = decoded_len;
   BIO_free_all(bmem);
   return buffer;
}

// Text format message parser:
// [enc_key_len][enc_key_b64][iv_b64][tag_b64][tag_b64]
// Returns PARSE_OK(0) or error code.
// Distinguishes binary buffers for enc_key_bin, iv_bin, tag_bin; lengths are back.
// The caller must free() all four buffers.
int parse_message_base64(const char *buf,
   int *out_enc_key_len,
   unsigned char **out_enc_key_bin, int *out_enc_key_bin_len,
   unsigned char **out_iv_bin, int *out_iv_len,
   unsigned char **out_tag_bin, int *out_tag_len,
   unsigned char **out_ct_bin, int *out_ct_len)
{
   if (!buf || !out_enc_key_len || !out_enc_key_bin || !out_iv_bin ||
      !out_tag_bin || !out_ct_bin) return PARSE_ERR_FORMAT;

   // Simple pass-through logic: search for 5 fields in square brackets
   const char *p = buf;
   char *fields[5] = { 0 };
   int i;

   for (i = 0; i < 5; ++i) {
      const char *l = strchr(p, '[');
      if (!l) return PARSE_ERR_FORMAT;

      const char *r = strchr(l + 1, ']');
      if (!r) return PARSE_ERR_FORMAT;

      int len = (int)(r - (l + 1));
      fields[i] = (char *)malloc(len + 1);

      if (!fields[i]) { 
         for (int j = 0; j < i; j++) free(fields[j]); 
         return PARSE_ERR_FORMAT; }
      memcpy(fields[i], l + 1, len);
      fields[i][len] = '\0';
      p = r + 1;
   }

   // поле0: encrypted_key_len (число)
   if (fields[0][0] == '\0') { 
      for (i = 0; i < 5; i++) free(fields[i]); 
      return PARSE_ERR_NUM; 
   }
   for (char *t = fields[0]; *t; ++t) {
      if (!isdigit((unsigned char)*t)) {
         for (i = 0; i < 5; i++) free(fields[i]);
         return PARSE_ERR_NUM;
      }
   }

   long v = strtol(fields[0], NULL, 10);
   if (v <= 0 || v > 65536) { 
      for (i = 0; i < 5; i++) free(fields[i]); 
      return PARSE_ERR_NUM; 
   }
   *out_enc_key_len = (int)v;

	// decode base64 fields -> binary buffers
   int tmp_len;

   unsigned char *enc_key_bin = base64_decode(fields[1], (int)strlen(fields[1]), &tmp_len);
   if (!enc_key_bin) { 
      for (i = 0; i < 5; i++) free(fields[i]); 
      return PARSE_ERR_FORMAT; 
   }
   *out_enc_key_bin = enc_key_bin; *out_enc_key_bin_len = tmp_len;

   unsigned char *iv_bin = base64_decode(fields[2], (int)strlen(fields[2]), &tmp_len);
   if (!iv_bin) { 
      free(enc_key_bin); 
      for (i = 0; i < 5; i++) free(fields[i]); 
      return PARSE_ERR_FORMAT; 
   }
   *out_iv_bin = iv_bin; *out_iv_len = tmp_len;

   unsigned char *tag_bin = base64_decode(fields[3], (int)strlen(fields[3]), &tmp_len);
   if (!tag_bin) { 
      free(enc_key_bin); 
      free(iv_bin); 
      for (i = 0; i < 5; i++) free(fields[i]); 
      return PARSE_ERR_FORMAT; 
   }
   *out_tag_bin = tag_bin; *out_tag_len = tmp_len;

   unsigned char *ct_bin = base64_decode(fields[4], (int)strlen(fields[4]), &tmp_len);
   if (!ct_bin) { 
      free(enc_key_bin); 
      free(iv_bin); 
      free(tag_bin); 
      for (i = 0; i < 5; i++) free(fields[i]); 
      return PARSE_ERR_FORMAT; 
   }
   *out_ct_bin = ct_bin; *out_ct_len = tmp_len;

   for (i = 0; i < 5; i++) free(fields[i]);
   return PARSE_OK;
}

DWORD WINAPI ClientHandler(LPVOID lpParam) {
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

#ifdef DEBUG
		printf("Received raw: %s\n", recvbuf);
#endif // DEBUG

      if (parse_message_base64(recvbuf,
         &enc_key_len,
         &enc_key_bin, &enc_key_bin_len,
         &iv_bin, &iv_len,
         &tag_bin, &tag_len,
         &ct_bin, &ct_len) != PARSE_OK) {

         printf("Failed to parse message from client.\n");
         // free if any allocated
         if (enc_key_bin) free(enc_key_bin);
         if (iv_bin) free(iv_bin);
         if (tag_bin) free(tag_bin);
         if (ct_bin) free(ct_bin);
         continue;
      }

      unsigned char *aes_key = NULL;
      size_t outlen = 0;
      EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(g_server_privkey, NULL);

      if (!pctx) {
         printf("EVP_PKEY_CTX_new failed\n");
         goto cleanup_packet;
      }

      if (EVP_PKEY_decrypt_init(pctx) <= 0) { 
         EVP_PKEY_CTX_free(pctx); 
         printf("decrypt_init failed\n"); 
         goto cleanup_packet; 
      }
      // set RSA OAEP padding
      if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0) { 
         EVP_PKEY_CTX_free(pctx); 
         printf("set padding failed\n"); 
         goto cleanup_packet; 
      }

#ifdef DEBUG
      printf("enc_key_bin_len: %d\n", enc_key_bin_len);
      printf("enc_key_bin (first 64 bytes): ");
      for (int i = 0; i < enc_key_bin_len && i < 64; i++)
         printf("%02X", (unsigned char)enc_key_bin[i]);
      printf("\n");

		// Debug: check RSA key details
      RSA *rsa = EVP_PKEY_get0_RSA(g_server_privkey);
      if (!rsa) {
         printf("g_server_privkey does not contain RSA key!\n");
      }
      else {
         int rsa_sz = RSA_size(rsa);
         const BIGNUM *n = NULL, *e = NULL, *d = NULL;
         RSA_get0_key(rsa, &n, &e, &d);
         printf("RSA_size=%d, has_private_d=%s\n", rsa_sz, (d ? "yes" : "no"));
      }
#endif // DEBUG

		// First call to get required size
      if (EVP_PKEY_decrypt(pctx, NULL, &outlen, enc_key_bin, (size_t)enc_key_bin_len) <= 0) {
         unsigned long err = ERR_get_error(); 
         char errbuf[256]; 
         ERR_error_string_n(err, errbuf, sizeof(errbuf));
         printf("EVP_PKEY_decrypt(get size) failed: %s\n", errbuf);
         EVP_PKEY_CTX_free(pctx);
         goto cleanup_packet;
      }

      aes_key = (unsigned char *)malloc(outlen);
      if (!aes_key) { EVP_PKEY_CTX_free(pctx); goto cleanup_packet; }

		// Second call to do decryption
      if (EVP_PKEY_decrypt(pctx, aes_key, &outlen, enc_key_bin, (size_t)enc_key_bin_len) <= 0) {
         unsigned long err = ERR_get_error(); char errbuf[256]; ERR_error_string_n(err, errbuf, sizeof(errbuf));
         printf("EVP_PKEY_decrypt failed: %s\n", errbuf);
         free(aes_key);
         aes_key = NULL;
         EVP_PKEY_CTX_free(pctx);
         goto cleanup_packet;
      }
      EVP_PKEY_CTX_free(pctx);

		// Check decrypted key length
      if (outlen != AES_KEY_LEN) {
         printf("Decrypted key length mismatch %zu\n", outlen);
         OPENSSL_cleanse(aes_key, outlen);
         free(aes_key);
         goto cleanup_packet;
      }

      // Decrypt ciphertext (in-place)
      int pt_len = aes_gcm_decrypt_inplace(ct_bin, ct_len, aes_key, iv_bin, iv_len, tag_bin);
      if (pt_len < 0) {
         printf("AES-GCM decryption failed (auth fail)\n");
         goto cleanup_packet;
      }

      // Ensure null-termination for text usage
      int printable_len = pt_len;
      if (printable_len >= BUFFER_SIZE - 1) printable_len = BUFFER_SIZE - 2;
      ct_bin[printable_len] = '\0';

      printf("[%s]: %s\n", senderName, (char *)ct_bin);

      // Broadcast plaintext to other clients
      char messageWithName[BUFFER_SIZE + MAX_NAME_LEN + 8];
      snprintf(messageWithName, sizeof(messageWithName), "\x1B[32m%s:\033[0m %s", senderName, (char *)ct_bin);

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

   cleanup_packet:
      if (enc_key_bin) free(enc_key_bin);
      if (iv_bin) free(iv_bin);
      if (tag_bin) free(tag_bin);
      if (ct_bin) free(ct_bin);
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