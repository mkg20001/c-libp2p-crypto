#include <crypto/util.h>
#include "aes.h"

CryptoAESParameters * aes_create(const unsigned char* key, const unsigned char* iv) {
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
  out->encrypt = c_new(EVP_CIPHER_CTX);
  out->decrypt = c_new(EVP_CIPHER_CTX);

  EVP_CIPHER_CTX_init(out->encrypt);
  EVP_EncryptInit(out->encrypt, mode, key, iv);
  EVP_CIPHER_CTX_init(out->decrypt);
  EVP_DecryptInit(out->decrypt, mode, key, iv);

  return out;
}