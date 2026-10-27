#include "api.h"

#define TWICE(x) ((x) + (x))

int use(void) {
    return TWICE((wide64) (1));
}
