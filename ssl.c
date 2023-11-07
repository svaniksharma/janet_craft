#include "ssl.h"
#include <openssl/rsa.h>
#include <janet.h>

// print where an error message happened
#define DIE() fprintf(stderr, "FAILED in file %s, line %d\n", __FILE__, __LINE__);

static EVP_PKEY_CTX *make_ctx(EVP_PKEY *key) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx) {
    DIE();
    return NULL;
  }
  return ctx;
}

/* Generates a 1024-bit RSA key pair and provides an SSL context */
struct rsa_info gen_rsa_key_pair() {
  struct rsa_info info = { 0 };
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!ctx) {
    DIE();
    return info;
  }
  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    DIE();
    return info;
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
    DIE();
    return info;
  }
  if (EVP_PKEY_keygen(ctx, &info.key) <= 0) {
    DIE();
    return info;
  }
  EVP_PKEY_CTX_free(ctx);
  info.encryption_ctx = make_ctx(info.key);
  if (!info.encryption_ctx)
    return info;
  if (EVP_PKEY_encrypt_init(info.encryption_ctx) <= 0) {
    DIE();
    return info;
  }
  info.decryption_ctx = make_ctx(info.key);
  if (!info.decryption_ctx)
    return info;
  if (EVP_PKEY_decrypt_init(info.decryption_ctx) <= 0) {
    DIE();
    return info;
  }
  return info;
}

/* Using a key pair, encrypts a buffer */
unsigned char *encrypt_buf(struct rsa_info *info, unsigned char *data, size_t data_size, size_t *encrypted_size) {
  size_t outlen = 0;
  unsigned char *out = NULL;
  if (EVP_PKEY_encrypt(info->encryption_ctx, NULL, &outlen, data, data_size) <= 0) {
    DIE();
    return NULL;
  }
  out = OPENSSL_malloc(outlen);
  if (!out) {
    DIE();
    return NULL;
  }
  if (EVP_PKEY_encrypt(info->encryption_ctx, out, &outlen, data, data_size) <= 0) {
    DIE();
    return NULL;
  }
  *encrypted_size = outlen;
  return out;
}

/* Using a key pair, decrypts a buffer */
unsigned char *decrypt_buf(struct rsa_info *info, unsigned char *data, size_t data_size, size_t *decrypted_size) {
  size_t outlen = 0;
  if (EVP_PKEY_decrypt(info->decryption_ctx, NULL, &outlen, data, data_size) <= 0)
    return NULL;
  unsigned char *out = OPENSSL_malloc(outlen);
  if (!out)
    return NULL;
  if (EVP_PKEY_decrypt(info->decryption_ctx, out, &outlen, data, data_size) <= 0)
    return NULL;
  *decrypted_size = outlen;
  return out;
}

/* Destroys an RSA info struct */
void destroy_rsa_key_pair(struct rsa_info *info) {
  if (info->encryption_ctx)
    EVP_PKEY_CTX_free(info->encryption_ctx);
  info->encryption_ctx = NULL;
  if (info->decryption_ctx)
    EVP_PKEY_CTX_free(info->decryption_ctx);
  info->decryption_ctx = NULL;
  if (info->key)
    EVP_PKEY_free(info->key);
  info->key = NULL;
}
