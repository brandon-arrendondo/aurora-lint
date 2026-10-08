#include <stdlib.h>

extern void *pool_take(size_t n);
extern void *pool_take_zeroed(size_t n);
#define take pool_take
#define take_zeroed pool_take_zeroed

char read_fresh_block(void) {
    char *p = take(8);
    return p[0];
}

char read_zeroed_block(void) {
    char *p = take_zeroed(8);
    return p[0];
}
