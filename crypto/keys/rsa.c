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

ProtobufCBinaryData pem_to_pkcs1(BIO * bio) {
}

int rsa_unmarshal_public_key(ProtobufCBinaryData data, Libp2pPubKey * out) { // convert pkcs1 buffer to PEM to openssl RSA public key encoded in libp2p pub key
  RSA *rsa = NULL;
  BIO * keybio = pkcs1_to_pem(data);
  if (keybio == NULL) return 1;
  rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
  BIO * bio = BIO_new(BIO_f_reliable());
  bio = BIO_push(bio, keybio);
  BIO_free_all(bio);
  if (rsa == NULL) return 1;
  out->data = (const void *) rsa;
  return 0;
}

int rsa_unmarshal_private_key(ProtobufCBinaryData data, Libp2pPrivKey * out) { // convert pkcs1 buffer to PEM to openssl RSA private key encoded in libp2p priv key
  RSA *rsa = NULL;
  BIO * keybio = pkcs1_to_pem(data);
  if (keybio == NULL) return 1;
  rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
  BIO * bio = BIO_new(BIO_f_reliable());
  bio = BIO_push(bio, keybio);
  BIO_free_all(bio);
  if (rsa == NULL) return 1;
  out->data = (const void *) rsa;
  out->pubKey->data = (const void *) rsa;
  return 0;
}

int rsa_marshal_public_key(Libp2pPubKey * key, ProtobufCBinaryData out) {
  RSA *rsa = (RSA *) key->data;
  char * buf = malloc(4096);
  BIO * bp = BIO_new_mem_buf((void*)buf, -1);
  PEM_write_bio_RSAPublicKey(bp, rsa);
  ProtobufCBinaryData pem = pem_to_pkcs1(bp);
  if (pem.data == NULL) return 1;
}

int rsa_marshal_private_key(Libp2pPrivKey * key, ProtobufCBinaryData out) {
  RSA *rsa = (RSA *) key->data;
  char * buf = malloc(4096);
  BIO * bp = BIO_new_mem_buf((void*)buf, -1);
  PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, NULL);
  ProtobufCBinaryData pem = pem_to_pkcs1(bp);
  if (pem.data == NULL) return 1;
}
