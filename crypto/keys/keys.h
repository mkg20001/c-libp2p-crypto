#include "common.h"
#include "rsa.h"

Libp2pPubKey * unmarshal_public_key(ProtobufCBinaryData data);
Libp2pPrivKey * unmarshal_private_key(ProtobufCBinaryData data);
