#include <gtest/gtest.h>
extern "C" {
  #include "crypto/aes/aes.h"
}

TEST(AES, init) {
  EXPECT_FALSE(aes_create((const unsigned char *)"2small", (const unsigned char *)"-")); // key must be 16/32 bytes long so this fails
  AES_CTX *ctx = NULL;
  ASSERT_NO_FATAL_FAILURE(ctx = aes_create((const unsigned char *)"1234567890123456", (const unsigned char *)"1234567890123456"));
  ASSERT_TRUE(ctx);
  ASSERT_NO_FATAL_FAILURE(aes_free(ctx));
}

TEST(AES, encryption_decryption) {
  unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";
  AES_CTX *ctx = aes_create((const unsigned char *)"1234567890123456", (const unsigned char *)"1234567890123456");
  ASSERT_TRUE(ctx);

  ASSERT_FALSE(aes_encrypt_update(ctx, plaintext, strlen("The quick brown fox jumps over the lazy dog")));
  ASSERT_FALSE(aes_encrypt_final(ctx));

  size_t len = ctx->encRes->len;
  unsigned char * cipher = aes_get_result(ctx->encRes);

  ASSERT_FALSE(aes_decrypt_update(ctx, cipher, len));
  ASSERT_FALSE(aes_decrypt_final(ctx));

  unsigned char * decipher = aes_get_result(ctx->decRes);
  ASSERT_FALSE(strcmp((char *)plaintext, (char *)decipher));

  aes_free(ctx);
  free(cipher);
  free(decipher);
}