#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>

typedef struct _AES_RES {
  size_t len;
  size_t alloc;
  unsigned char * res;
} AES_RES;

typedef struct _AES_CTX {
  EVP_CIPHER_CTX* encrypt;
  AES_RES* encRes;
  EVP_CIPHER_CTX* decrypt;
  AES_RES* decRes;
} AES_CTX;

AES_CTX * aes_create(const unsigned char* key, const unsigned char* iv);
void aes_free(AES_CTX * ctx);
unsigned char * aes_get_result(AES_RES * res);
int aes_decrypt_update(AES_CTX * _ctx, unsigned char * cipher, size_t cipher_len);
int aes_decrypt_final(AES_CTX * _ctx);
int aes_encrypt_update(AES_CTX * _ctx, unsigned char * plain, size_t plain_len);
int aes_encrypt_final(AES_CTX * _ctx);
