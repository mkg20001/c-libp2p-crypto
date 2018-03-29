#include <crypto/util.h>
#include "keys.h"

Libp2pPubKey * unmarshal_public_key(ProtobufCBinaryData data) {
  PublicKey * pubKey = public_key__unpack(NULL, data.len, data.data);
  Libp2pPubKey * out = c_new(Libp2pPubKey);
  out->type = pubKey->type;
  switch(pubKey->type) {
    case KEY_TYPE__RSA: {
      rsa_unmarshal_public_key(pubKey->data, out);
      return out;
    }
    case KEY_TYPE__Ed25519: case KEY_TYPE__Secp256k1: {
      return NULL; // TODO: add
    }
    default: {
      return NULL; // TODO: intelligent error handling
    }
  }
}

Libp2pPrivKey * unmarshal_private_key(ProtobufCBinaryData data) {
  PrivateKey * privKey = private_key__unpack(NULL, data.len, data.data);
  Libp2pPrivKey * out = c_new(Libp2pPrivKey);
  out->type = privKey->type;
  switch(privKey->type) {
    case KEY_TYPE__RSA: {
      out->data = rsa_unmarshal_public_key(privKey->data);
      return out;
    }
    case KEY_TYPE__Ed25519: case KEY_TYPE__Secp256k1: {
      return NULL; // TODO: add
    }
    default: {
      return NULL; // TODO: intelligent error handling
    }
  }
}
