#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <janet.h>

struct rsa_info {
  EVP_PKEY *key;
  EVP_PKEY_CTX *encryption_ctx;
  EVP_PKEY_CTX *decryption_ctx;
};

struct rsa_info gen_rsa_key_pair();
unsigned char *encrypt_buf(struct rsa_info *info, unsigned char *data, size_t data_size, size_t *encrypted_size);
unsigned char *decrypt_buf(struct rsa_info *info, unsigned char *data, size_t data_size, size_t *decrypted_size);
void destroy_rsa_key_pair(struct rsa_info *info);

// print where an error message happened
#define DIE() fprintf(stderr, "FAILED in file %s, line %d\n", __FILE__, __LINE__);

// helper functions
static EVP_PKEY_CTX *make_ctx(EVP_PKEY *key) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx) {
    DIE();
    return NULL;
  }
  return ctx;
}

// Janet-specific data structures 

static int rsa_info_gc(void *data, size_t len) {
  (void) len;
  janet_table_deinit((JanetTable *) data);
  return 0;
}

static int rsa_info_gcmark(void *data, size_t len) {
  (void) len;
  janet_mark(janet_wrap_table((JanetTable *) data));
  return 0;
}

static const JanetAbstractType rsa_info_type = {
  .name = "rsa_info",
  .gc = rsa_info_gc,
  .gcmark = rsa_info_gcmark,
  .get = NULL,
  .put = NULL,
  .marshal = NULL,
  .unmarshal = NULL,
  .tostring = NULL,
  .compare = NULL,
  .hash = NULL,
  .next = NULL,
  .call = NULL,
  .length = NULL,
  .bytes = NULL,
};

/* These basically call the C functions described in ssl.h (scroll down for more) */

static Janet make_rsa_info(int32_t argc, Janet *argv) {
  // create a Janet table with 3 elements
  JanetTable *rsa = (JanetTable *) janet_abstract(&rsa_info_type, sizeof(JanetTable));
  rsa->gc = (JanetGCObject){0, NULL};
  janet_table_init_raw(rsa, 3);
  // Put the pointers into the table
  struct rsa_info info = gen_rsa_key_pair();
  if (!info.key || !info.encryption_ctx || !info.decryption_ctx)
    return janet_wrap_nil();
  janet_table_put(rsa, janet_wrap_string(janet_string("key", 3)), janet_wrap_pointer(info.key));
  janet_table_put(rsa, janet_wrap_string(janet_string("ectx", 4)), janet_wrap_pointer(info.encryption_ctx));
  janet_table_put(rsa, janet_wrap_string(janet_string("dctx", 4)), janet_wrap_pointer(info.decryption_ctx));
  return janet_wrap_table(rsa);
}

static Janet rsa_encrypt(int32_t argc, Janet *argv) {
  // Get the RSA info (Janet table) and the data (Janet buffer)
  // Use the C function to encrypt the buffer
  // Create new Janet buffer and copy contents 
}

static Janet rsa_decrypt(int32_t argc, Janet *argv) {
  // Get the RSA info (Janet table) and the data (Janet buffer)
  // Use the C function to encrypt the buffer
  // Create new Janet buffer and copy contents 
}

static const JanetReg cfuns[] = {
  {"new", make_rsa_info, "Creates a new rsa_info datatype"},
  {"encrypt", rsa_encrypt, "Encrypts data with an rsa_info struct"},
  {"decrypt", rsa_decrypt, "Decrypts data with an rsa_info struct"},
  {NULL, NULL, NULL}
};

JANET_MODULE_ENTRY(JanetTable *env) {
  janet_cfuns(env, "rsa", cfuns);
  janet_register_abstract_type(&rsa_info_type);
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
