#include "rsa.h"
#include <crypto/util.h>
#include <memory.h>

#define PEM_PREFIX "-----BEGIN RSA PRIVATE KEY-----\n"
#define PEM_SUFFIX "\n-----END RSA PRIVATE KEY-----"

/* --- PKCS1 <-> PEM --- */

typedef enum _KeyLevel {
  KEY_PRIVATE = 0,
  KEY_PUBLIC = 1
} KeyLevel;

RSA * pkcs1_to_pem(ProtobufCBinaryData data, KeyLevel l) {
  const char * b64 = base64Encode(data);
  char * str = malloc(strlen(PEM_PREFIX) + strlen(PEM_SUFFIX) + strlen(b64) + 1);
  strcpy(str, PEM_PREFIX);
  strcat(str, b64);
  strcat(str, PEM_SUFFIX);
  str[strlen(PEM_PREFIX) + strlen(PEM_SUFFIX) + strlen(b64)] = '\0';
  BIO * keybio = BIO_new_mem_buf((void*)str, -1);
  if (keybio == NULL) {
    free(str);
    free((void *)b64);
    return NULL;
  }
  RSA * rsa = NULL;
  switch(l) {
    case KEY_PRIVATE: {
      PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
      break;
    }
    case KEY_PUBLIC: {
      PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
      break;
    }
  }
  free(str);
  free((void *)b64);
  BIO_free_all(keybio);
  return rsa;
}

ProtobufCBinaryData pem_to_pkcs1(BIO * bio) {
}

/* --- unmarshal --- */

int rsa_unmarshal_public_key(ProtobufCBinaryData data, Libp2pPubKey * out) { // convert pkcs1 buffer to PEM to openssl RSA public key encoded in libp2p pub key
  RSA *rsa = pkcs1_to_pem(data, KEY_PUBLIC);
  if (rsa == NULL) return 1;
  out->data = (const void *) rsa;
  return 0;
}

int rsa_unmarshal_private_key(ProtobufCBinaryData data, Libp2pPrivKey * out) { // convert pkcs1 buffer to PEM to openssl RSA private key encoded in libp2p priv key
  RSA *rsa = pkcs1_to_pem(data, KEY_PRIVATE);
  if (rsa == NULL) return 1;
  out->data = (const void *) rsa;
  out->pubKey->data = (const void *) rsa;
  return 0;
}

/* --- marshal --- */

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

/* --- free --- */
