#include "common.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

int rsa_unmarshal_public_key(ProtobufCBinaryData data, Libp2pPubKey * out);
int rsa_unmarshal_private_key(ProtobufCBinaryData data, Libp2pPrivKey * out);
