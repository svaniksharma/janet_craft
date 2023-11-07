#ifndef SSL_JANET_H
#define SSL_JANET_H

#include <stdio.h>
#include <openssl/evp.h>

struct rsa_info {
  EVP_PKEY *key;
  EVP_PKEY_CTX *encryption_ctx;
  EVP_PKEY_CTX *decryption_ctx;
};

struct rsa_info gen_rsa_key_pair();
unsigned char *encrypt_buf(struct rsa_info *info, unsigned char *data, size_t data_size, size_t *encrypted_size);
unsigned char *decrypt_buf(struct rsa_info *info, unsigned char *data, size_t data_size, size_t *decrypted_size);
void destroy_rsa_key_pair(struct rsa_info *info);

#endif
