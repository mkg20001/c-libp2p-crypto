# c-libp2p-crypto

The libp2p-crypto library ported to C

## WIP

## ToDos (Add js-like api)
  - [ ] [`crypto.hmac`](#hmac)
    - [ ] [`create(hash, secret, callback)`](#createhash-secret-callback)
      - [ ] [`digest(data, callback)`](#digestdata-callback)
  - [ ] [`crypto.aes`](#aes)
    - [x] [`create(key, iv, callback)`](#createkey-iv-callback)
      - [ ] [`encrypt(data, callback)`](#encryptdata-callback)
      - [ ] [`decrypt(data, callback)`](#decryptdata-callback)
  - [ ] [`keys`](#keys)
    - [ ] [`generateKeyPair(type, bits, callback)`](#generatekeypairtype-bits-callback)
    - [ ] [`generateEphemeralKeyPair(curve, callback)`](#generateephemeralkeypaircurve-callback)
    - [ ] [`keyStretcher(cipherType, hashType, secret, callback)`](#keystretcherciphertype-hashtype-secret-callback)
    - [ ] [`marshalPublicKey(key[, type], callback)`](#marshalpublickeykey-type-callback)
    - [ ] [`unmarshalPublicKey(buf)`](#unmarshalpublickeybuf)
    - [ ] [`marshalPrivateKey(key[, type])`](#marshalprivatekeykey-type)
    - [ ] [`unmarshalPrivateKey(buf, callback)`](#unmarshalprivatekeybuf-callback)
    - [ ] [`import(pem, password, callback)`](#importpem-password-callback)