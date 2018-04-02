#include "rsa.h"
#include <crypto/util.h>
#include <memory.h>

#define PEM_PRIVATE_PREFIX "-----BEGIN RSA PRIVATE KEY-----\n"
#define PEM_PRIVATE_SUFFIX "\n-----END RSA PRIVATE KEY-----"
#define PEM_PUBLIC_PREFIX "-----BEGIN RSA PUBLIC KEY-----\n"
#define PEM_PUBLIC_SUFFIX "\n-----END RSA PUBLIC KEY-----"

/* --- PKCS1 <-> PEM --- */

typedef enum _KeyLevel {
  KEY_PRIVATE = 0,
  KEY_PUBLIC = 1
} KeyLevel;

RSA * pkcs1_to_pem(ProtobufCBinaryData data, KeyLevel l) {
  char * pemPrefix;
  char * pemSuffix;
  switch(l) {
    case KEY_PRIVATE: {
      pemPrefix = PEM_PRIVATE_PREFIX;
      pemSuffix = PEM_PRIVATE_SUFFIX;
      break;
    }
    case KEY_PUBLIC: {
      pemPrefix = PEM_PUBLIC_PREFIX;
      pemSuffix = PEM_PUBLIC_SUFFIX;
      break;
    }
    default: {
      return NULL;
    }
  }
  const char * b64 = base64Encode(data);
  char * str = malloc(strlen(pemPrefix) + strlen(pemSuffix) + strlen(b64) + 1);
  strcpy(str, pemPrefix);
  strcat(str, b64);
  strcat(str, pemSuffix);
  str[strlen(pemPrefix) + strlen(pemSuffix) + strlen(b64)] = '\0';
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

ProtobufCBinaryData pem_to_pkcs1(RSA * rsa, KeyLevel l) {
  ProtobufCBinaryData data;
  data.len = 0;
  data.data = NULL;

  if (l != KEY_PRIVATE && l != KEY_PUBLIC) return data;

  BIO *bio;
  BUF_MEM *bufferPtr;

  bio = BIO_new(BIO_s_mem());

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line

  switch(l) {
    case KEY_PRIVATE: {
      PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
      break;
    }
    case KEY_PUBLIC: {
      PEM_write_bio_RSAPublicKey(bio, rsa);
      break;
    }
  }

  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);

  char * pem = (*bufferPtr).data;

  char * pemPrefix;
  char * pemSuffix;
  switch(l) {
    case KEY_PRIVATE: {
      pemPrefix = PEM_PRIVATE_PREFIX;
      pemSuffix = PEM_PRIVATE_SUFFIX;
      break;
    }
    case KEY_PUBLIC: {
      pemPrefix = PEM_PUBLIC_PREFIX;
      pemSuffix = PEM_PUBLIC_SUFFIX;
      break;
    }
  }

  size_t len = strlen(pem) - (strlen(pemPrefix) + strlen(pemSuffix));

  char * b64 = malloc(len + 1);
  memcpy(b64, pem + strlen(pemPrefix), len);
  b64[len] = '\0';

  data = base64Decode(b64); // TODO: remove newlines from PEM_write* to fix this assert

  return data;
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
  ProtobufCBinaryData pkcs1 = pem_to_pkcs1(rsa, KEY_PUBLIC);
  if (pkcs1.data == NULL) return 1;
  out.data = pkcs1.data;
  out.len = pkcs1.len;
  return 0;
}

int rsa_marshal_private_key(Libp2pPrivKey * key, ProtobufCBinaryData out) {
  RSA * rsa = (RSA * ) key->data;
  ProtobufCBinaryData pkcs1 = pem_to_pkcs1(rsa, KEY_PRIVATE);
  if (pkcs1.data == NULL) return 1;
  out.data = pkcs1.data;
  out.len = pkcs1.len;
  return 0;
}

/* --- free --- */

void rsa_free_public_key_data(Libp2pPubKey * key) {
  if (key->data == NULL) return;
  RSA * rsa = (RSA *) key->data;
  RSA_free(rsa);
}

void rsa_free_private_key_data(Libp2pPrivKey * key) {
  if (key->data == NULL) return;
  RSA * rsa = (RSA *) key->data;
  RSA_free(rsa);
}
