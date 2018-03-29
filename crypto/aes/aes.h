#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>

typedef struct _CryptoAESParameters {
  EVP_CIPHER_CTX* encrypt;
  EVP_CIPHER_CTX* decrypt;
} CryptoAESParameters;
CryptoAESParameters * crypto_aes_create(const unsigned char* key, const unsigned char* iv);