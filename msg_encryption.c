#include "msg_encryption.h"


unsigned char group_key[SENDER_KEY_LEN];
int group_key_set = 0;


char *base64_encode(const unsigned char *input, int length)
{
   BIO *b64 = BIO_new(BIO_f_base64());
   BIO *mem = BIO_new(BIO_s_mem());
   b64 = BIO_push(b64, mem);

   BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
   BIO_write(b64, input, length);
   BIO_flush(b64);

   BUF_MEM *buffer_ptr;
   BIO_get_mem_ptr(b64, &buffer_ptr);

   char *result = malloc(buffer_ptr->length + 1);
   memcpy(result, buffer_ptr->data, buffer_ptr->length);
   result[buffer_ptr->length] = '\0';

   BIO_free_all(b64);
   return result;
}


int base64_decode(const char *input, int length, unsigned char **out)
{
   BIO *b64 = BIO_new(BIO_f_base64());
   BIO *mem = BIO_new_mem_buf(input, length);
   mem = BIO_push(b64, mem);

   BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);

   *out = malloc(length);
   int decoded_len = BIO_read(mem, *out, length);

   BIO_free_all(mem);
   return decoded_len;
}


int sender_key_generate(sender_key_t *out)
{
   if (!out) return 0;

   // random AES-256 key
   if (RAND_bytes(out->key, SENDER_KEY_LEN) != 1)
      return 0;

   // random key_id
   RAND_bytes((unsigned char *)&out->key_id, sizeof(uint32_t));

   out->counter = 0;
   return 1;
}



int derive_message_iv(const sender_key_t *sk, unsigned char iv_out[IV_LEN])
{
   unsigned char ctr_buf[8];
   unsigned char hmac[32];

   if (!sk) return 0;

   // convert counter to bytes
   uint64_t ctr = sk->counter;
   for (int i = 0; i < 8; i++) {
      ctr_buf[7 - i] = (ctr >> (i * 8)) & 0xFF;
   }

   unsigned int mac_len = 0;
   HMAC(EVP_sha256(),
      sk->key, SENDER_KEY_LEN,
      ctr_buf, sizeof(ctr_buf),
      hmac, &mac_len);

   memcpy(iv_out, hmac, IV_LEN);
   return 1;
}



int aes256_gcm_encrypt(
   unsigned char *buf, int len,
   const unsigned char key[SENDER_KEY_LEN],
   const unsigned char iv[IV_LEN],
   unsigned char tag[TAG_LEN])
{
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   if (!ctx) return -1;

   int outlen = 0;
   int ret = -1;

   if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
      goto done;

   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);

   if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
      goto done;

   if (EVP_EncryptUpdate(ctx, buf, &outlen, buf, len) != 1)
      goto done;

   if (EVP_EncryptFinal_ex(ctx, buf + outlen, &len) != 1)
      goto done;

   outlen += len;

   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
   ret = outlen;

done:
   EVP_CIPHER_CTX_free(ctx);
   return ret;
}



int aes256_gcm_decrypt(
   unsigned char *buf, int len,
   const unsigned char key[SENDER_KEY_LEN],
   const unsigned char iv[IV_LEN],
   const unsigned char tag[TAG_LEN])
{
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   if (!ctx) return -1;

   int outlen = 0;
   int ret = -1;

   if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
      goto done;

   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);

   if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
      goto done;

   if (EVP_DecryptUpdate(ctx, buf, &outlen, buf, len) != 1)
      goto done;

   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag);

   if (EVP_DecryptFinal_ex(ctx, buf + outlen, &len) != 1)
      goto done;

   ret = outlen + len;

done:
   EVP_CIPHER_CTX_free(ctx);
   return ret;
}