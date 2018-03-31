#ifndef LIBP2P_CRYPTO_COMMON_FILES
#define LIBP2P_CRYPTO_COMMON_FILES 1
#include <protos/key.pb-c.h>

typedef struct _Libp2pPubKey {
    KeyType type;
    const void * data;
} Libp2pPubKey;

typedef struct _Libp2pPrivKey {
    KeyType type;
    const void * data;
    Libp2pPubKey * pubKey;
} Libp2pPrivKey;
#endif