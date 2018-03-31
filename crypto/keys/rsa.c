#include "rsa.h"
#include <crypto/util.h>
#include <memory.h>

#define PEM_PREFIX "-----BEGIN RSA PRIVATE KEY-----\n"
#define PEM_SUFFIX "\n-----END RSA PRIVATE KEY-----"

BIO * pkcs1_to_pem(ProtobufCBinaryData data) {
  const char * b64 = base64Encode(data);
  char * str = malloc(strlen(PEM_PREFIX) + strlen(PEM_SUFFIX) + strlen(b64) + 1);
  strcpy(str, PEM_PREFIX);
  strcat(str, b64);
  strcat(str, PEM_SUFFIX);
  str[strlen(PEM_PREFIX) + strlen(PEM_SUFFIX) + strlen(b64)] = '\0';
  BIO * keybio = BIO_new_mem_buf((void*)str, -1);
  if (keybio == NULL) {
    return NULL;
  }
  return keybio;
}

int rsa_unmarshal_public_key(ProtobufCBinaryData data, Libp2pPubKey * out) { // convert pkcs1 buffer to PEM to openssl RSA private key encoded in libp2p priv key
  RSA *rsa = NULL;
  BIO * keybio = pkcs1_to_pem(data);
  if (keybio == NULL) return 1;
  rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
  if (rsa == NULL) return 1;
  out->data = (const void *) rsa;
  return 0;
}

int rsa_unmarshal_private_key(ProtobufCBinaryData data, Libp2pPrivKey * out) { // convert pkcs1 buffer to PEM to openssl RSA private key encoded in libp2p priv key
  RSA *rsa = NULL;
  BIO * keybio = pkcs1_to_pem(data);
  if (keybio == NULL) return 1;
  rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
  if (rsa == NULL) return 1;
  out->data = (const void *) rsa;
  return 0;
}