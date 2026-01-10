#ifndef MSG_ENCRYPTION_H
#define MSG_ENCRYPTION_H


#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>


#define SENDER_KEY_LEN 32      // AES-256
#define SENDER_KEY_ID_LEN 4
#define IV_LEN 12
#define TAG_LEN 16

extern unsigned char group_key[SENDER_KEY_LEN];
extern int group_key_set;


typedef struct {
   uint32_t key_id;
   unsigned char key[SENDER_KEY_LEN];
   uint64_t counter;
} sender_key_t;

// Base64 encode/decode. Returns allocated buffer (needs free).
char *base64_encode(const unsigned char *input, int length);
int base64_decode(const char *input, int length, unsigned char **out);

//// Generate a fresh Sender Key bundle
int sender_key_generate(sender_key_t *out);

// Derive IV = HMAC_SHA256(sender_key, counter)[0:12]
int derive_message_iv(const sender_key_t *sk, unsigned char iv_out[IV_LEN]);

// AES-256-GCM decrypt
int aes256_gcm_decrypt(
   unsigned char *buf, int len,
   const unsigned char key[SENDER_KEY_LEN],
   const unsigned char iv[IV_LEN],
   const unsigned char tag[TAG_LEN]
);

// AES-256-GCM encrypt
int aes256_gcm_encrypt(
   unsigned char *buf, int len,
   const unsigned char key[SENDER_KEY_LEN],
   const unsigned char iv[IV_LEN],
   unsigned char tag[TAG_LEN]
);

#endif // MSG_ENCRYPTION_H