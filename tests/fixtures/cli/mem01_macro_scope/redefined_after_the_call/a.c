#include <stdlib.h>
#include "macros.h"
static char *gbuf;

void log_it(void);

void f(void) {
    free(gbuf);
    log_it();
    gbuf = NULL;
}

#undef log_it
#define log_it() ((void)0)
