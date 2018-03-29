#include "aes.h"

CryptoAESParameters * crypto_aes_create(const unsigned char* key, const unsigned char* iv) {
  const EVP_CIPHER *mode;
  switch(strlen((const char *)key)) {
    case 16: {
      mode = EVP_aes_128_ctr();
      break;
    }
    case 32: {
      mode = EVP_aes_256_ctr();
      break;
    }
    default: {
      return NULL;
    }
  }

  CryptoAESParameters * out = (CryptoAESParameters *)malloc(sizeof(CryptoAESParameters));

  EVP_CIPHER_CTX_init(out->encrypt);
  EVP_EncryptInit_ex(out->encrypt, mode, NULL, key, iv);
  EVP_CIPHER_CTX_init(out->decrypt);
  EVP_DecryptInit(out->decrypt, mode, key, iv);

  return out;
}