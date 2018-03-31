#include <memory.h>
#include <stdlib.h>
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
    char * c = (char *)malloc(2);
    memcpy(c, hex + i * 2, 2);
    c[2] = '\0';
    uint8_t c2 = (uint8_t)strtol(c, NULL, 16);
    data.data[i] = c2;
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
  out[data.len] = '\0';

  return out;
}