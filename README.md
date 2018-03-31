# c-libp2p-crypto

The libp2p-crypto library ported to C

## WIP

## ToDos (Add js-like api)
  -  [ ] [`crypto.hmac`](#hmac)
     -  [ ] [`create(hash, secret, callback)`](#createhash-secret-callback)
       -  [ ] [`digest(data, callback)`](#digestdata-callback)
  -  [x] [`crypto.aes`](#aes)
     -  [x] [`create(key, iv, callback)`](#createkey-iv-callback)
        -  [x] [`encrypt(data, callback)`](#encryptdata-callback)
        -  [x] [`decrypt(data, callback)`](#decryptdata-callback)
  -  [ ] [`keys`](#keys)
     -  [ ] [`generateKeyPair(type, bits, callback)`](#generatekeypairtype-bits-callback)
     -  [ ] [`generateEphemeralKeyPair(curve, callback)`](#generateephemeralkeypaircurve-callback)
     -  [ ] [`keyStretcher(cipherType, hashType, secret, callback)`](#keystretcherciphertype-hashtype-secret-callback)
     -  [ ] [`marshalPublicKey(key[, type], callback)`](#marshalpublickeykey-type-callback)
     -  [ ] [`unmarshalPublicKey(buf)`](#unmarshalpublickeybuf)
     -  [ ] [`marshalPrivateKey(key[, type])`](#marshalprivatekeykey-type)
     -  [ ] [`unmarshalPrivateKey(buf, callback)`](#unmarshalprivatekeybuf-callback)
     -  [ ] [`import(pem, password, callback)`](#importpem-password-callback)

## API

###  `<aes.h>`

######  `AES_CTX * aes_create(const unsigned char * key, const unsigned char key *)`

> Creates a new AES context with the key and initialization vector

> AES mode is determined by the key size (16=aes-128-ctr, 32=aes-256-ctr)

######  `int aes_decrypt_update(AES_CTX * _ctx, unsigned char * cipher, size_t cipher_len)`

> Decrypts `cipher` using the AES context and stores the value in `_ctx->decRes`

######  `int aes_decrypt_final(AES_CTX * _ctx)`

> Finalizes the decryption and stores the result in `_ctx->decRes`

######  `int aes_encrypt_update(AES_CTX * _ctx, unsigned char * plain, size_t plain_len)`

> Encrypts `plain` using the AES context and stores the value in `_ctx->encRes`

######  `int aes_encrypt_final(AES_CTX * _ctx)`

> Finalizes the encryption and stores the result in `_ctx->encRes`

###### `void aes_free(AES_CTX * ctx)`

> Frees an AES context

###### `unsigned char * aes_get_result(AES_RES * res)`

> Gets the currently stored value of the AES context result and re-creates the result object

#### Example

```c
unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";
AES_CTX *ctx = aes_create((const unsigned char *)"1234567890123456", (const unsigned char *)"1234567890123456");

if (aes_encrypt_update(ctx, plaintext, strlen("The quick brown fox jumps over the lazy dog"))) return NULL; // error
if (aes_encrypt_final(ctx)) return NULL; // error

size_t len = ctx->encRes->len;
unsigned char * cipher = aes_get_result(ctx->encRes);

if (aes_decrypt_update(ctx, cipher, len)) return NULL; // error
if (aes_decrypt_final(ctx)) return NULL; // error

unsigned char * decipher = aes_get_result(ctx->decRes);
if (!strcmp((char *)plaintext, (char *)decipher)) return NULL; // input does not match output
```
