#include <crypto/util.h>
#include "aes.h"

AES_CTX * aes_create(const unsigned char* key, const unsigned char* iv) {
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

  AES_CTX * out = (AES_CTX *)malloc(sizeof(AES_CTX));
  out->encrypt = EVP_CIPHER_CTX_new();
  out->decrypt = EVP_CIPHER_CTX_new();

  if (out->encrypt == NULL || out->decrypt == NULL) return NULL;

  EVP_CIPHER_CTX_init(out->encrypt);
  EVP_EncryptInit(out->encrypt, mode, key, iv);
  EVP_CIPHER_CTX_init(out->decrypt);
  EVP_DecryptInit(out->decrypt, mode, key, iv);

  return out;
}

char * aes_decrypt_update(AES_CTX * _ctx, unsigned char * cipher, size_t cipher_len, size_t * outlen) {
  EVP_CIPHER_CTX *ctx = _ctx->decrypt;
  unsigned char * plain = (unsigned char *)malloc(cipher_len + 256);
  int L = 0;
  if (EVP_DecryptUpdate(ctx, plain, &L, cipher, (int)cipher_len) != 1) return NULL;
  plain[L] = '\0'; // add null terminator
  *outlen += L;
  return (char *)plain;
}

char * aes_decrypt_final(AES_CTX * _ctx, size_t * outlen) {
  EVP_CIPHER_CTX *ctx = _ctx->decrypt;
  unsigned char * plain = (unsigned char *)malloc(256);
  int L = 0;
  if (EVP_DecryptFinal(ctx, plain, &L) != 1) return NULL;
  EVP_CIPHER_CTX_free(ctx); // free mem
  plain[L] = '\0'; // add null terminator
  *outlen += L;
  return (char *)plain;
}

char * aes_encrypt_update(AES_CTX * _ctx, unsigned char * plain, size_t plain_len, size_t * outlen) {
  EVP_CIPHER_CTX *ctx = _ctx->encrypt;
  unsigned char * cipher = (unsigned char *)malloc(plain_len + 256);
  int L = 0;
  if (EVP_EncryptUpdate(ctx, cipher, &L, plain, (int)plain_len) != 1) return NULL;
  cipher[L] = '\0'; // add null terminator
  *outlen += L;
  return (char *)cipher;
}

char * aes_encrypt_final(AES_CTX * _ctx, size_t * outlen) {
  EVP_CIPHER_CTX *ctx = _ctx->encrypt;
  unsigned char * cipher = (unsigned char *)malloc(256);
  int L = 0;
  if (EVP_EncryptFinal(ctx, cipher, &L) != 1) return NULL;
  EVP_CIPHER_CTX_free(ctx); // free mem
  cipher[L] = '\0'; // add null terminator
  *outlen += L;
  return (char *)cipher;
}