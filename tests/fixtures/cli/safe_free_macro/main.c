/* `p` is freed-and-nulled by the my_safefree output macro (include/safefree.h).
 * Without seeing the macro's `(p) = NULL`, MEM30-C reports a double-free on the
 * second my_safefree and a use-after-free on the later read. With Phase 2c-iii
 * the macro's null is applied, so neither fires (a second safe-free is
 * free(NULL); a read yields NULL, not a dangling pointer). */
#include <stdlib.h>
#include "safefree.h"

void cleanup(void) {
    char *p = malloc(16);
    my_safefree(p);
    my_safefree(p);     /* free(NULL) — NOT a double-free */
    if (p) {            /* p is NULL here — NOT use-after-free */
        do_something(p);
    }
}
