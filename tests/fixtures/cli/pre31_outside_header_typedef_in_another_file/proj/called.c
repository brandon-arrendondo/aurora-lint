#include "api.h"

#define TWICE(x) ((x) + (x))

static int wrap(int v) {
    return (wide64) (v);
}

int use_wrap(void) {
    return TWICE(wrap(1));
}
