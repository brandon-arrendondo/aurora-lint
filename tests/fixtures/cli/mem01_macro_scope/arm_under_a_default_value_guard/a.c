#include <stdlib.h>
#include "report.h"

static char *cache;

static void report(void)
{
    if (cache != NULL) {
        cache[0] = 'x';
    }
}

void flush(void)
{
    free(cache);
    report();
    cache = NULL;
}
