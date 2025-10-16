#pragma once

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
//#include "openssl/applink.c"


// Error codes for message parsing
#define PARSE_OK 0
#define PARSE_ERR_FORMAT -1
#define PARSE_ERR_NUM -2


// base64 encode. returns allocated buffer (needs free).
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

// base64 decode. returns allocated buffer (needs free).
// out_len is filled with the length in bytes.
unsigned char *base64_decode(const char *b64, int b64_len, int *out_len) {
   BIO *b64bio = NULL, *bmem = NULL;
   unsigned char *buffer = NULL;
   int decoded_len = 0;

   b64bio = BIO_new(BIO_f_base64());
   BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL); // no newlines
   bmem = BIO_new_mem_buf((void *)b64, b64_len);
   bmem = BIO_push(b64bio, bmem);

   // allocate temporary buffer: b64_len (approximately) is enough
   buffer = (unsigned char *)malloc(b64_len + 1);
   if (!buffer) { BIO_free_all(bmem); return NULL; }

   decoded_len = BIO_read(bmem, buffer, b64_len);
   if (decoded_len <= 0) { 
      free(buffer); 
      BIO_free_all(bmem); 
      return NULL; 
   }

   *out_len = decoded_len;
   BIO_free_all(bmem);
   return buffer;
}


// Text format message parser:
// [enc_key_len][enc_key_b64][iv_b64][tag_b64][encrypted_msg]
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
         return PARSE_ERR_FORMAT;
      }
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
