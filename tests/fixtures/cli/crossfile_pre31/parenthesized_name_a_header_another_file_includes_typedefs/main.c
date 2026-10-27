#include "api.h"

#define TWICE(x) ((x) + (x))

static int wrap(int v) {
    return (step) (v);
}

int use(void) {
    return TWICE(wrap(1));
}
