#include "MySocket.h"
#include "MsgEncrypt.h"

// Generate sender key (Group Key)
int generate_group_key(unsigned char *group_key_out) {
	if (RAND_bytes(group_key_out, SENDER_KEY_LEN) != 1) {
		fprintf(stderr, "RAND_bytes failed generating group key\n");
		return GENERATE_KEY_FAIL;
	}
	return SUCCESS;
}

// Encode and send group key to server
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


// Client send thread
// client is a pointer to Client struct
ClientSendMessage(client) {
	my_socket_t sock = client->socket;
	char buffer[CLIENT_BUFFER_SIZE];

	unsigned char iv[IV_LEN];
	unsigned char tag[TAG_LEN];

	while (1) {

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

		if (client->name) {
			char name_prefix[MAX_NAME_LEN + 3];
			snprintf(name_prefix, sizeof(name_prefix), "[%s] ", client->name);
			size_t name_prefix_len = strlen(name_prefix);
			memmove(buffer + name_prefix_len, buffer, plain_len + 1);
			memcpy(buffer, name_prefix, name_prefix_len);
			plain_len += name_prefix_len;
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

		// Encrypt message
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

		char *b64_iv = base64_encode(iv, IV_LEN);
		char *b64_tag = base64_encode(tag, TAG_LEN);
		char *b64_ct = base64_encode((unsigned char *)buffer, ciphertext_len);

		if (!b64_iv || !b64_tag || !b64_ct) {
			fprintf(stderr, "base64 encode failed\n");
			free(b64_iv); free(b64_tag); free(b64_ct);
			break;
		}

		// Final message: [GMSG][iv][tag][ciphertext]
		char final_msg[CLIENT_BUFFER_SIZE * 2];
		snprintf(final_msg, sizeof(final_msg),
			"[GMSG][%s][%s][%s]", b64_iv, b64_tag, b64_ct);

		free(b64_iv);
		free(b64_tag);
		free(b64_ct);

		// Send it
		if (send(sock, final_msg, (int)strlen(final_msg), 0) == MY_SEND_ERROR) {
			fprintf(stderr, "send() failed: %d\n", my_get_last_error());
			break;
		}
	}

	my_shutdown_send(sock);
	return 0;
}

// Client receive thread
// lpParam is a pointer to socket
ClientRecieveMessage(lpParam) {
	my_socket_t sock = (my_socket_t)lpParam;
	char buf[CLIENT_BUFFER_SIZE];

	while (1) {

		int r = recv(sock, buf, CLIENT_BUFFER_SIZE - 1, 0);
		if (r <= 0) {
			printf("\nServer closed connection\n");
			return 1;
		}

		buf[r] = '\0';

		// Check for group key
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

		// Check for group message
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


int main()
{
	Client client;
	client.socket = -1;
	struct addrinfo *result = NULL, *ptr = NULL, hints;
	THREAD_TYPE threads[THREAD_COUNT];
	char ip[IP_LENGTH];

	INIT_WINSOCK();

	EnableVTMode();

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	printf("Enter server IP address: ");
	fgets(ip, sizeof(ip), stdin);

	// Remove trailing newline
	ip[strcspn(ip, "\r\n")] = '\0';

	if (getaddrinfo(ip, DEFAULT_PORT, &hints, &result) != 0) {
		perror("getaddrinfo failed");
		WSA_CLEANUP();
		return 1;
	}

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		client.socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (client.socket < 0) continue;

		if (connect(client.socket, ptr->ai_addr, (int)ptr->ai_addrlen) == 0) break;

		my_close(client.socket);
		client.socket = -1;
	}

	freeaddrinfo(result);

	if (client.socket < 0) {
		printf("Unable to connect to server!\n");
		WSA_CLEANUP();
		return 1;
	}

	if (generate_group_key(group_key) != SUCCESS || send_group_key(client.socket, group_key) != SUCCESS) {
		printf("Failed to generate/send group key\n");
		my_close(client.socket);
		WSA_CLEANUP();
		return 1;
	}
	group_key_set = 1;
	printf("Local group key generated and sent\n");

	printf("Enter name (16 characters max): ");
	if (fgets(client.name, MAX_NAME_LEN, stdin)) {
		size_t len = strlen(client.name);
		if (len && client.name[len - 1] == '\n') client.name[len - 1] = '\0';
	}

	char name_msg[MAX_NAME_LEN + CODE_LENGTH + 1];
	snprintf(name_msg, sizeof(name_msg), "[NAME]%s", client.name);

	if (send(client.socket, name_msg, (int)strlen(name_msg), 0) < 0)
		perror("send failed");

	THREAD_CREATE(threads[SEND_THREAD], ClientSendMessage, &client);
	THREAD_CREATE(threads[RECV_THREAD], ClientRecieveMessage, (void *)(uintptr_t)client.socket);

	for (int i = 0; i < THREAD_COUNT; i++)
		THREAD_JOIN(threads[i]);

	my_close(client.socket);
	WSA_CLEANUP();

	return 0;
}
