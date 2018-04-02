#include "common.h"
#include "rsa.h"

Libp2pPubKey * unmarshal_public_key(ProtobufCBinaryData data);
Libp2pPrivKey * unmarshal_private_key(ProtobufCBinaryData data);
ProtobufCBinaryData marshal_public_key(Libp2pPubKey * key);
ProtobufCBinaryData marshal_private_key(Libp2pPrivKey * key);
void free_public_key(Libp2pPubKey * key);
void free_private_key(Libp2pPrivKey * key);
