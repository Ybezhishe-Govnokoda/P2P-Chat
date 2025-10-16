#pragma once

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>


#define TAG_LEN 16
#define AES_KEY_LEN 16


// Load an EVP private key from a PEM file
EVP_PKEY *load_private_key(const char *filename) {
   FILE *fp = fopen(filename, "rb");
   if (!fp) { perror("open privkey"); return NULL; }
   EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
   fclose(fp);
   return pkey;
}

// Load an EVP public key from a PEM file
EVP_PKEY *load_public_key(const char *filename) {
	FILE *fp = fopen(filename, "rb");
	if (!fp) { perror("open pubkey"); return NULL; }
	EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);
	return pkey;
}


// AES encryption function. Returns ciphertext length, or -1 on error
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

// Decrypt the AES key using RSA private key
const unsigned char *AES_key_decrypt(
   EVP_PKEY *g_server_privkey,
	const unsigned char *enc_key_bin,
	int enc_key_bin_len
   ) {

   unsigned char *aes_key = NULL;
   size_t outlen = 0;
   EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(g_server_privkey, NULL);

   if (!pctx) {
      printf("EVP_PKEY_CTX_new failed\n");
   }

   if (EVP_PKEY_decrypt_init(pctx) <= 0) {
      EVP_PKEY_CTX_free(pctx);
      printf("decrypt_init failed\n");
   }
   // set RSA OAEP padding
   if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
      EVP_PKEY_CTX_free(pctx);
      printf("set padding failed\n");
   }

   // First call to get required size
   if (EVP_PKEY_decrypt(pctx, NULL, &outlen, enc_key_bin, (size_t)enc_key_bin_len) <= 0) {
      printf("EVP_PKEY_decrypt(get size) failed\n");
      EVP_PKEY_CTX_free(pctx);
   }

   aes_key = (unsigned char *)malloc(outlen);
   if (!aes_key) { EVP_PKEY_CTX_free(pctx); }

   // Second call to do decryption
   if (EVP_PKEY_decrypt(pctx, aes_key, &outlen, enc_key_bin, (size_t)enc_key_bin_len) <= 0) {
      printf("EVP_PKEY_decrypt failed\n");
      free(aes_key);
      aes_key = NULL;
      EVP_PKEY_CTX_free(pctx);
   }
   EVP_PKEY_CTX_free(pctx);

   // Check decrypted key length
   if (outlen != AES_KEY_LEN) {
      printf("Decrypted key length mismatch %zu\n", outlen);
      OPENSSL_cleanse(aes_key, outlen);
      free(aes_key);
   }

	return aes_key ? aes_key : NULL;
}
