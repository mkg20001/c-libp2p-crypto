#include "rsa.h"
#include <crypto/util.h>

int rsa_unmarshal_public_key(ProtobufCBinaryData data, Libp2pPubKey * out) { // TODO: add
  RSA *rsa = NULL;
  const char * str = (const char *)data.data;
  BIO * keybio = BIO_new_mem_buf((void*)str, -1);
  if (keybio == NULL) {
    return 1;
  }
  rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
  if (rsa == NULL) return 1;
  out->data = (const void *) rsa;
  return 0;
}

int rsa_unmarshal_private_key(ProtobufCBinaryData data, Libp2pPrivKey * out) { // TODO: add
  RSA *rsa = NULL;
  const unsigned char * str = data.data;
  BIO * keybio = BIO_new_mem_buf((void*)str, -1);
  if (keybio == NULL) {
    return 1;
  }
  rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
  if (rsa == NULL) return 1;
  out->data = (const void *) rsa;
  return 0;
}