#include "common.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

int rsa_unmarshal_public_key(ProtobufCBinaryData data, Libp2pPubKey * out);
int rsa_unmarshal_private_key(ProtobufCBinaryData data, Libp2pPrivKey * out);
int rsa_marshal_public_key(Libp2pPubKey * key, ProtobufCBinaryData out);
int rsa_marshal_private_key(Libp2pPrivKey * key, ProtobufCBinaryData out);
void rsa_free_public_key_data(Libp2pPubKey * key);
void rsa_free_private_key_data(Libp2pPrivKey * key);
