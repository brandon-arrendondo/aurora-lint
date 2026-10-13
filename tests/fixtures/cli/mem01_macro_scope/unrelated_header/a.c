#include <stdlib.h>

static char *gbuf;

void log_it(void);

void f(void) {
    free(gbuf);
    log_it();
    gbuf = NULL;
}
