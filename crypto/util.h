#include <malloc.h>

#define c_new(type) \
    ((type*)malloc(sizeof(type)))
