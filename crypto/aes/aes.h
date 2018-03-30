#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>

typedef struct _AES_CTX {
  EVP_CIPHER_CTX* encrypt;
  EVP_CIPHER_CTX* decrypt;
} AES_CTX;

AES_CTX * aes_create(const unsigned char* key, const unsigned char* iv);
void aes_free(AES_CTX * ctx);
char * aes_decrypt_update(AES_CTX * _ctx, unsigned char * cipher, size_t cipher_len, size_t * outlen);
char * aes_decrypt_final(AES_CTX * _ctx, size_t * outlen);
char * aes_encrypt_update(AES_CTX * _ctx, unsigned char * plain, size_t plain_len, size_t * outlen);
char * aes_encrypt_final(AES_CTX * _ctx, size_t * outlen);
