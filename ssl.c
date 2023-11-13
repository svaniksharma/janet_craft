#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <janet.h>

#define WRAP_JANET_STRING(key, len) janet_wrap_string(janet_string((const uint8_t *) key, len))

struct rsa_info {
  EVP_PKEY *key;
  EVP_PKEY_CTX *encryption_ctx;
  EVP_PKEY_CTX *decryption_ctx;
};

struct rsa_info gen_rsa_key_pair();
unsigned char *encrypt_buf(struct rsa_info *info, unsigned char *data, size_t data_size, size_t *encrypted_size);
unsigned char *decrypt_buf(struct rsa_info *info, unsigned char *data, size_t data_size, size_t *decrypted_size);
void destroy_rsa_key_pair(struct rsa_info *info);
char *calc_sha1_hex_digest(unsigned char *shared_secret, size_t shared_secret_len, 
			   unsigned char *der_encoded_public_key, size_t der_encoded_public_key_len, int *negative, unsigned char **hex_buf);

// print where an error message happened
#define DIE() { \
  fprintf(stderr, "In file %s on line %d:\n", __FILE__, __LINE__); \
  ERR_print_errors_fp(stdout); \
}

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
  struct rsa_info info = { 0 };
  JanetTable *rsa = (JanetTable *) data;
  info.key = janet_unwrap_pointer(janet_table_get(rsa, WRAP_JANET_STRING("key", 3)));
  info.encryption_ctx = janet_unwrap_pointer(janet_table_get(rsa, WRAP_JANET_STRING("ectx", 4)));
  info.decryption_ctx = janet_unwrap_pointer(janet_table_get(rsa, WRAP_JANET_STRING("dctx", 4)));
  destroy_rsa_key_pair(&info);
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

/* Janet Bindings */

static size_t auth_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
  JanetBuffer *buf = (JanetBuffer *) userdata;
  janet_buffer_push_cstring(buf, ptr);
  return nmemb;
}

/* Send authentication request to url */
static Janet send_auth_req(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 1);
  JanetString url = janet_unwrap_string(argv[0]);
  CURL *handle = curl_easy_init();
  if (!handle) {
    return janet_wrap_nil();
  }
  JanetBuffer *buffer = janet_buffer(1);
  curl_easy_setopt(handle, CURLOPT_URL, (char *) url);
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, auth_callback);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, buffer);
  CURLcode res = curl_easy_perform(handle);
  curl_easy_cleanup(handle);
  return janet_wrap_buffer(buffer);
}

static Janet make_rsa_info(int32_t argc, Janet *argv) {
  // create a Janet table with 3 elements
  JanetTable *rsa = (JanetTable *) janet_abstract(&rsa_info_type, sizeof(JanetTable));
  rsa->gc = (JanetGCObject){0, NULL};
  janet_table_init_raw(rsa, 3);
  // Put the pointers into the table
  struct rsa_info info = gen_rsa_key_pair();
  if (!info.key || !info.encryption_ctx || !info.decryption_ctx)
    return janet_wrap_nil();
  janet_table_put(rsa, WRAP_JANET_STRING("key", 3), janet_wrap_pointer(info.key));
  janet_table_put(rsa, WRAP_JANET_STRING("ectx", 4), janet_wrap_pointer(info.encryption_ctx));
  janet_table_put(rsa, WRAP_JANET_STRING("dctx", 4), janet_wrap_pointer(info.decryption_ctx));
  return janet_wrap_table(rsa);
}

static Janet get_der(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 1);
  JanetTable *rsa = janet_unwrap_table(argv[0]);
  EVP_PKEY *key = janet_unwrap_pointer(janet_table_get(rsa, WRAP_JANET_STRING("key", 3)));
  size_t der_data_len = i2d_PUBKEY(key, NULL);
  if (der_data_len <= 0) {
    DIE();
    return janet_wrap_nil();
  }
  unsigned char *der_data = OPENSSL_malloc(der_data_len);
  if (der_data == NULL) {
    DIE();
    return janet_wrap_nil();
  }
  unsigned char *der_data_buf = der_data;
  size_t outlen = i2d_PUBKEY(key, &der_data);
  if (outlen != der_data_len || der_data != der_data_buf + der_data_len) {
    DIE();
    return janet_wrap_nil();
  }
  JanetBuffer *buffer = janet_buffer(der_data_len);
  janet_buffer_push_bytes(buffer, der_data_buf, der_data_len);
  OPENSSL_free(der_data_buf);
  return janet_wrap_buffer(buffer);
}

static Janet rsa_encrypt(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 2);
  // Get the RSA info (Janet table) and the data (Janet buffer)
  JanetTable *rsa = janet_unwrap_table(argv[0]);
  JanetBuffer *buf = janet_unwrap_buffer(argv[1]);
  // Use the C function to encrypt the buffer
  struct rsa_info info;
  info.key = janet_unwrap_pointer(janet_table_get(rsa, WRAP_JANET_STRING("key", 3)));
  info.encryption_ctx = janet_unwrap_pointer(janet_table_get(rsa, WRAP_JANET_STRING("ectx", 4)));
  info.decryption_ctx = janet_unwrap_pointer(janet_table_get(rsa, WRAP_JANET_STRING("dctx", 4)));
  size_t encrypted_size = 0;
  unsigned char *encrypted = encrypt_buf(&info, buf->data, buf->count, &encrypted_size);
  if (encrypted_size <= 0 || !encrypted) {
    return janet_wrap_nil();
  }
  // Create new Janet buffer and copy contents
  JanetBuffer *buffer = janet_buffer(encrypted_size);
  janet_buffer_push_bytes(buffer, encrypted, encrypted_size);
  OPENSSL_free(encrypted);
  return janet_wrap_buffer(buffer);
}

static Janet rsa_decrypt(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 2);
  // Get the RSA info (Janet table) and the data (Janet buffer)
  JanetTable *rsa = janet_unwrap_table(argv[0]);
  JanetBuffer *buf = janet_unwrap_buffer(argv[1]);
  // unwrap each element in array
  // Use the C function to encrypt the buffer
  struct rsa_info info;
  info.key = janet_unwrap_pointer(janet_table_get(rsa, WRAP_JANET_STRING("key", 3)));
  info.encryption_ctx = janet_unwrap_pointer(janet_table_get(rsa, WRAP_JANET_STRING("ectx", 4)));
  info.decryption_ctx = janet_unwrap_pointer(janet_table_get(rsa, WRAP_JANET_STRING("dctx", 4)));
  size_t decrypted_size = 0;
  unsigned char *decrypted = decrypt_buf(&info, buf->data, buf->count, &decrypted_size);
  if (decrypted_size <= 0 || !decrypted) {
    return janet_wrap_nil();
  }
  // Create new Janet buffer and copy contents 
  JanetBuffer *buffer = janet_buffer(decrypted_size);
  janet_buffer_push_bytes(buffer, decrypted, decrypted_size);
  OPENSSL_free(decrypted);
  return janet_wrap_buffer(buffer);
}

static Janet sha1_hexdigest(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 2);
  JanetBuffer *shared_secret = janet_unwrap_buffer(argv[0]);
  JanetBuffer *der_public_key = janet_unwrap_buffer(argv[1]);
  int negative = 0;
  unsigned char *hex_ptr = NULL;
  char *hex = calc_sha1_hex_digest(shared_secret->data, shared_secret->count, der_public_key->data, der_public_key->count, &negative, &hex_ptr);
  if (!hex) {
    return janet_wrap_nil();
  }
  JanetBuffer *hex_buf = janet_buffer(strlen(hex));
  if (negative)
    janet_buffer_push_bytes(hex_buf, (unsigned char *) "-", 1);
  janet_buffer_push_bytes(hex_buf, (unsigned char *) hex, strlen(hex));
  JanetString hex_str = janet_string(hex_buf->data, hex_buf->count);
  janet_buffer_deinit(hex_buf);
  OPENSSL_free(hex_ptr);
  return janet_wrap_string(hex_str);
}

static const JanetReg cfuns[] = {
  {"get", send_auth_req, "Sends an HTTPS request to the provided url"},
  {"new", make_rsa_info, "Creates a new rsa_info datatype"},
  {"der", get_der, "get a DER encoded public key"},
  {"encrypt", rsa_encrypt, "Encrypts data with an rsa_info struct"},
  {"decrypt", rsa_decrypt, "Decrypts data with an rsa_info struct"},
  {"sha1", sha1_hexdigest, "SHA1 hex digest"},
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
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024) <= 0) {
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
    destroy_rsa_key_pair(&info);
    return info;
  }
  if (EVP_PKEY_CTX_set_rsa_padding(info.encryption_ctx, RSA_PKCS1_PADDING) <= 0) {
    DIE();
    destroy_rsa_key_pair(&info);
    return info;
  }
  if (EVP_PKEY_CTX_set_rsa_padding(info.decryption_ctx, RSA_PKCS1_PADDING) <= 0) {
    DIE();
    destroy_rsa_key_pair(&info);
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
  if (EVP_PKEY_decrypt(info->decryption_ctx, NULL, &outlen, data, data_size) <= 0) {
    DIE();
    return NULL;
  }
  unsigned char *out = OPENSSL_malloc(outlen);
  if (!out) {
    DIE();
    return NULL;
  }
  if (EVP_PKEY_decrypt(info->decryption_ctx, out, &outlen, data, data_size) <= 0) {
    DIE();
    return NULL;
  }
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

/* Updates SHA1 digest */
static int update_digest(EVP_MD_CTX *ctx, unsigned char *data, size_t data_len) {
  if (EVP_DigestUpdate(ctx, data, data_len) <= 0) {
    DIE();
    return 0; // fail 
  }
  return 1; // success
}

/* Calculates Minecraft hex digest */
char *calc_sha1_hex_digest(unsigned char *shared_secret, size_t shared_secret_len, 
			   unsigned char *der_encoded_public_key, size_t der_encoded_public_key_len, int *negative, unsigned char **hex_ptr) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  if (!ctx) {
    DIE();
    return NULL;
  }
  if (EVP_DigestInit(ctx, EVP_sha1()) <= 0) {
    DIE();
    return NULL;
  }
  if (!update_digest(ctx, (unsigned char *) "", 0))
    return NULL;
  if (!update_digest(ctx, shared_secret, shared_secret_len))
    return NULL;
  if (!update_digest(ctx, der_encoded_public_key, der_encoded_public_key_len))
    return NULL;
  unsigned char digest[EVP_MAX_MD_SIZE] = { 0 };
  unsigned int digest_len = sizeof(digest);
  if (EVP_DigestFinal(ctx, digest, &digest_len) <= 0) {
    DIE();
    return NULL;
  }
  EVP_MD_CTX_free(ctx);
  BIGNUM *bn = BN_bin2bn(digest, digest_len, NULL);
  if (BN_is_bit_set(bn, 159))  {
    size_t tmp_len = BN_num_bytes(bn);
    unsigned char *tmp = OPENSSL_malloc(tmp_len);
    if (!tmp) {
      DIE();
      return NULL;
    }
    BN_bn2bin(bn, tmp);
    for (int i = 0; i < tmp_len; i++)
      tmp[i] = ~tmp[i];
    BN_bin2bn(tmp, tmp_len, bn);
    BN_add_word(bn, 1);
    OPENSSL_free(tmp);
    *negative = 1;
  } else {
    *negative = 0;
  }
  char *hex = BN_bn2hex(bn);
  char *hex_start = hex;
  *hex_ptr = (unsigned char *) hex_start;
  int len = strlen(hex);
  for (int i = 0; i < len; i++)
    if (*hex == '0')
      ++hex;
  BN_free(bn);
  return hex;
}
