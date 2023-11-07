#include "ssl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define MAX_SIZE 10000

int main(int argc, char *argv[]) {
  char buf[MAX_SIZE+1] = { 0 };
  struct rsa_info info = gen_rsa_key_pair();
  assert(info.encryption_ctx != NULL);
  assert(info.decryption_ctx != NULL);
  assert(info.key != NULL);
  while (fgets(buf, MAX_SIZE, stdin)) {
    size_t len = strlen(buf)+1;
    size_t encrypted_size = 0;
    unsigned char *encrypted = encrypt_buf(&info, (unsigned char *) buf, len, &encrypted_size);
    assert(encrypted_size > 0);
    assert(encrypted != NULL);
    size_t decrypted_size = 0;
    unsigned char *decrypted = decrypt_buf(&info, encrypted, encrypted_size, &decrypted_size);
    assert(decrypted_size == len);
    assert(!strncmp(buf, (char *) decrypted, len-1));
    printf("%s", ((char *) decrypted)); // includes a newline character already
    memset(buf, 0, MAX_SIZE+1);
  }
  destroy_rsa_key_pair(&info);
  assert(info.encryption_ctx == NULL);
  assert(info.decryption_ctx == NULL);
  assert(info.key == NULL);
  return 0;
}
