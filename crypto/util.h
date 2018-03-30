#include <malloc.h>
#include <protobuf-c/protobuf-c.h>

#define c_new(type) \
    ((type*)malloc(sizeof(type)))

ProtobufCBinaryData fromHex(const char * hex);
char * toHex(ProtobufCBinaryData data);