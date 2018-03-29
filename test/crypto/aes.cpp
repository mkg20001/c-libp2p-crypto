#include <gtest/gtest.h>
extern "C" {
  #include "crypto/aes/aes.h"
}

TEST(AES, init) {
  ASSERT_NO_FATAL_FAILURE(crypto_aes_create((const unsigned char *)"1234567890123456", (const unsigned char *)"1234567890123456"));
}