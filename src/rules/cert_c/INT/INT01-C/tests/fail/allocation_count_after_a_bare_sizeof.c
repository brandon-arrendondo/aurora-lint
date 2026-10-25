/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - an int element count after a bare sizeof
 *
 * sizeof gives the element size; n, the int after it, is the number of
 * elements, and it is held in an int.
 */
#include <stdlib.h>

struct item { int id; };

int item_total(void);

void *make_items(void) {
    int n = item_total();
    return calloc(sizeof(struct item), n);
}
