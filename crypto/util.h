#include <malloc.h>
#include <protobuf-c/protobuf-c.h>
#include <openssl/bio.h>

#define c_new(type) \
    ((type*)malloc(sizeof(type)))

ProtobufCBinaryData fromHex(const char * hex);
char * toHex(ProtobufCBinaryData data);
char * base64Encode(ProtobufCBinaryData data);
ProtobufCBinaryData base64Decode(char * base64);
