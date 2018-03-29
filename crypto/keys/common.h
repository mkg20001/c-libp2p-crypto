#include <protos/key.pb-c.h>

typedef struct _Libp2pPubKey {
    KeyType type;
    const void * data;
} Libp2pPubKey;

typedef struct _Libp2pPrivKey {
    KeyType type;
    const void * data;
    Libp2pPubKey pubKey;
} Libp2pPrivKey;