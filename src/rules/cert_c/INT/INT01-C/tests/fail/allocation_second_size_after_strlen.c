/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - an int count after a strlen element size
 *
 * strlen returns a size_t, so the first size is the right type; count, the
 * second, is held in an int.
 */
#include <stdlib.h>
#include <string.h>

int copies_wanted(void);

void *make_copies(const char *s) {
    int count = copies_wanted();
    return calloc(strlen(s), count);
}
