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

  out->encRes = c_new(AES_RES);
  out->decRes = c_new(AES_RES);

  return out;
}

void aes_free(AES_CTX * ctx) {
  if (ctx == NULL) return;
  if (ctx->encrypt != NULL) EVP_CIPHER_CTX_free(ctx->encrypt);
  if (ctx->decrypt != NULL) EVP_CIPHER_CTX_free(ctx->decrypt);
  if (ctx->encRes != NULL) free(ctx->encRes);
  if (ctx->decRes != NULL) free(ctx->decRes);
  free(ctx);
}

AES_RES * aes_init_res() {
  AES_RES * r = c_new(AES_RES);
  r->len = 0;
  r->alloc = 0;
}

unsigned char * aes_get_result(AES_RES * res) { // will get cur res->res and re-create
  if (!res->len) {
    free(res->res);
    free(res);
    res = aes_init_res();
    return (unsigned char *)"";
  }
  unsigned char * r = res->res;
  r[res->len] = '\0'; // add null terminator
  free(res);
  res = aes_init_res();
  return res->res;
}

void extend_res(AES_RES * res, size_t wanted) { // re-malloc res->res to wanted bytes
  if (res->alloc >= wanted) return; // already big enough
  unsigned char * cur = res->res;
  res->alloc = wanted;
  res->res = (unsigned char *)malloc(wanted);
  memcpy(res->res, cur, res->len);
}

int aes_decrypt_update(AES_CTX * _ctx, unsigned char * cipher, size_t cipher_len) {
  EVP_CIPHER_CTX *ctx = _ctx->decrypt;
  AES_RES *res = _ctx->decRes;
  extend_res(res, cipher_len + 256);
  unsigned char * plain = (unsigned char *)malloc(cipher_len + 256);
  int L = 0;
  if (EVP_DecryptUpdate(ctx, plain, &L, cipher, (int)cipher_len) != 1) return 1;
  memcpy(res->res + res->len, plain, (size_t)L);
  res->len += L;
  return 0;
}

int aes_decrypt_final(AES_CTX * _ctx) {
  EVP_CIPHER_CTX *ctx = _ctx->decrypt;
  AES_RES *res = _ctx->decRes;
  extend_res(res, 256);
  unsigned char * plain = (unsigned char *)malloc(256);
  int L = 0;
  if (EVP_DecryptFinal(ctx, plain, &L) != 1) return 1;
  EVP_CIPHER_CTX_free(ctx); // free mem
  memcpy(res->res + res->len, plain, (size_t)L);
  res->len += L;
  return 0;
}

int aes_encrypt_update(AES_CTX * _ctx, unsigned char * plain, size_t plain_len) {
  EVP_CIPHER_CTX *ctx = _ctx->encrypt;
  AES_RES *res = _ctx->encRes;
  extend_res(res, plain_len + 256);
  unsigned char * cipher = (unsigned char *)malloc(plain_len + 256);
  int L = 0;
  if (EVP_EncryptUpdate(ctx, cipher, &L, plain, (int)plain_len) != 1) return 1;
  memcpy(res->res + res->len, plain, (size_t)L);
  res->len += L;
  return 0;
}

int aes_encrypt_final(AES_CTX * _ctx) {
  EVP_CIPHER_CTX *ctx = _ctx->encrypt;
  AES_RES *res = _ctx->encRes;
  extend_res(res, 256);
  unsigned char * cipher = (unsigned char *)malloc(256);
  int L = 0;
  if (EVP_EncryptFinal(ctx, cipher, &L) != 1) return 1;
  EVP_CIPHER_CTX_free(ctx); // free mem
  memcpy(res->res + res->len, cipher, (size_t)L);
  res->len += L;
  return 0;
}