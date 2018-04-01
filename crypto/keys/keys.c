#include <crypto/util.h>
#include "keys.h"

/* --- unmarshal --- */

Libp2pPubKey * unmarshal_public_key(ProtobufCBinaryData data) {
  PublicKey * pubKey = public_key__unpack(NULL, data.len, data.data);
  if (pubKey == NULL) return NULL; // TODO: intelligent error handling

  Libp2pPubKey * out = c_new(Libp2pPubKey);
  out->type = pubKey->type;

  int err;

  switch(pubKey->type) {
    case KEY_TYPE__RSA: {
      err = rsa_unmarshal_public_key(pubKey->data, out);
      break;
    }
    case KEY_TYPE__Ed25519: case KEY_TYPE__Secp256k1: default: { // TODO: add those
      err = 1;
    }
  }

  public_key__free_unpacked(pubKey, NULL);

  if (err) goto free_and_stop;
  return out;

  free_and_stop:
    free(out);
    return NULL;
}

Libp2pPrivKey * unmarshal_private_key(ProtobufCBinaryData data) {
  PrivateKey * privKey = private_key__unpack(NULL, data.len, data.data);
  if (privKey == NULL) return NULL; // TODO: intelligent error handling

  Libp2pPrivKey * out = c_new(Libp2pPrivKey);
  out->pubKey = c_new(Libp2pPubKey);
  out->type = privKey->type;

  int err;

  switch(privKey->type) {
    case KEY_TYPE__RSA: {
      err = rsa_unmarshal_private_key(privKey->data, out);
      break;
    }
    case KEY_TYPE__Ed25519: case KEY_TYPE__Secp256k1: default: { // TODO: add those
      err = 1;
    }
  }

  private_key__free_unpacked(privKey, NULL);

  if (err) goto free_and_stop;
  return out;

  free_and_stop: // TODO: intelligent error handling
    free(out->pubKey);
    free(out);
    return NULL;
}

/* --- marshal --- */

ProtobufCBinaryData marshal_public_key(Libp2pPubKey * key) {
  ProtobufCBinaryData data;
  data.data = NULL;
  data.len = 0;

  int err;

  switch(key->type) {
    case KEY_TYPE__RSA: {
      err = rsa_marshal_public_key(key, data);
      break;
    }
    case KEY_TYPE__Ed25519: case KEY_TYPE__Secp256k1: default: { // TODO: add those
      goto free_and_stop;
    }
  }

  if (err) goto free_and_stop;
  return data;

  free_and_stop:
    free_data(data);
    return data;
}

ProtobufCBinaryData marshal_private_key(Libp2pPrivKey * key) {
  ProtobufCBinaryData data;
  data.data = NULL;
  data.len = 0;

  int err;

  switch(key->type) {
    case KEY_TYPE__RSA: {
      err = rsa_marshal_private_key(key, data);
      break;
    }
    case KEY_TYPE__Ed25519: case KEY_TYPE__Secp256k1: default: { // TODO: add those
      goto free_and_stop;
    }
  }

  if (err) goto free_and_stop;
  return data;

  free_and_stop:
    free_data(data);
    return data;
}

/* --- free --- */

void free_public_key(Libp2pPubKey * key) {
  if (key == NULL) return;

  switch(key->type) {
    case KEY_TYPE__RSA: {
      rsa_free_public_key_data((void *) key->data);
      break;
    }
  }

  free(key);
}

void free_private_key(Libp2pPrivKey * key) {
  if (key == NULL) return;
  free_public_key(key->pubKey);

  switch(key->type) {
    case KEY_TYPE__RSA: {
      rsa_free_private_key_data((void *) key->data);
      break;
    }
  }

  free(key);
}
