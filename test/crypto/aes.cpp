#include <gtest/gtest.h>
extern "C" {
  #include "crypto/aes/aes.h"
}

TEST(AES, init) {
  EXPECT_FALSE(aes_create((const unsigned char *)"2small", (const unsigned char *)"-")); // key must be 16/32 bytes long so this fails
  AES_CTX *ctx = NULL;
  ASSERT_NO_FATAL_FAILURE(ctx = aes_create((const unsigned char *)"1234567890123456", (const unsigned char *)"1234567890123456"));
  ASSERT_TRUE(ctx);
}

TEST(AES, encryption_decryption) {
  unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";
  AES_CTX *ctx = aes_create((const unsigned char *)"1234567890123456", (const unsigned char *)"1234567890123456");
  ASSERT_TRUE(ctx);

  size_t len = 0;
  char cipher[200];
  strcpy(cipher, aes_encrypt_update(ctx, plaintext, strlen("The quick brown fox jumps over the lazy dog"), &len));
  strcat(cipher, aes_encrypt_final(ctx, &len));
  ASSERT_TRUE(cipher);

  size_t len2 = 0;
  char decipher[200];
  strcpy(decipher, aes_decrypt_update(ctx, (unsigned char *)decipher, len, &len2));
  strcat(decipher, aes_decrypt_final(ctx, &len2));
  fprintf(stderr, (char *)plaintext);
  fprintf(stderr, "\n!=\n");
  fprintf(stderr, (char *)decipher);
  ASSERT_EQ(plaintext, (unsigned char *)decipher);
}