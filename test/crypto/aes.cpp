#include <gtest/gtest.h>
extern "C" {
  #include "crypto/aes/aes.h"
}

TEST(AES, init) {
  EXPECT_FALSE(crypto_aes_create((const unsigned char *)"2small", (const unsigned char *)"-")); // key must be 16/32 bytes long so this fails
  ASSERT_NO_FATAL_FAILURE(crypto_aes_create((const unsigned char *)"1234567890123456", (const unsigned char *)"1234567890123456"));
}