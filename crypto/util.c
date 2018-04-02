#include <memory.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "util.h"

ProtobufCBinaryData fromHex(const char * hex) {
  size_t len = strlen(hex);
  ProtobufCBinaryData data;
  data.data = NULL;
  data.len = 0;
  if (len % 2 != 0) return data;
  len /= 2;

  data.len = len;

  data.data = malloc(len + 1);
  for (int i = 0; i < len; ++i) {
    char * c = (char *)malloc(3);
    memcpy(c, hex + i * 2, 2);
    c[2] = '\0';
    uint8_t c2 = (uint8_t)strtol(c, NULL, 16);
    data.data[i] = c2;
    free(c);
  }

  data.data[len] = '\0';

  return data;
}

char * toHex(ProtobufCBinaryData data) {
  char * out;

  if (data.data == NULL || data.len == 0)
    return NULL;
  
  out = malloc(data.len * 2 + 1);
  for (int i = 0; i < data.len; ++i) {
    sprintf(out + i * 2, "%02X", data.data[i]);
  }
  out[data.len * 2] = '\0';

  return out;
}

// from http://doctrina.org/Base64-With-OpenSSL-C-API.html

char * Base64Encode(const unsigned char* buffer, size_t length) { //Encodes a binary safe base 64 string
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem()); // TODO: fix leak
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
  BIO_write(bio, buffer, (int)length);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);

  return (*bufferPtr).data;
}

size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
  size_t len = strlen(b64input),
          padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;

  return (len*3)/4 - padding;
}

int Base64Decode(char* b64message, unsigned char** buffer, size_t* length) { //Decodes a base64 encoded string
  BIO *bio, *b64;

  size_t decodeLen = calcDecodeLength(b64message);
  *buffer = (unsigned char*)malloc(decodeLen + 1);
  (*buffer)[decodeLen] = '\0';

  bio = BIO_new_mem_buf(b64message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
  *length = (size_t) BIO_read(bio, *buffer, (int) strlen(b64message));
  assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
  BIO_free_all(bio);

  return (0); //success
}

char * base64Encode(ProtobufCBinaryData data) {
  return Base64Encode(data.data, data.len);
}

ProtobufCBinaryData base64Decode(char * base64) {
  ProtobufCBinaryData out;
  out.len = 0;
  out.data = NULL;
  if (Base64Decode(base64, &out.data, &out.len)) return out;
  return out;
}

void free_data(ProtobufCBinaryData data) {
  if (data.data != NULL) {
    free(data.data);
    data.data = NULL;
  }
}
