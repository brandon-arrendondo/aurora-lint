#include <stdlib.h>

static char *gbuf;

void log_it(void);
#define log_it() ((void)0)
#undef log_it

void f(void) {
    free(gbuf);
    log_it();
    gbuf = NULL;
}
