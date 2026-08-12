/*
 * Rule: DCL30-C
 * Status: PASS - Out-param assigned a heap-derived pointer VALUE (valid)
 */

#include <stdlib.h>

static void *grow_array(void *ptr, size_t n, size_t sz) {
    return realloc(ptr, n * sz);
}

int get_names(char ***out_names, size_t *out_size, char *arg) {
    char *tmp, **nnames;

    while (arg) {
        nnames = grow_array(*out_names, 1 + *out_size, sizeof(char *));
        if (!nnames)
            return -1;
        *out_names = nnames;  /* Safe: nnames holds a heap-derived pointer value */

        (*out_size)++;
        arg = tmp;
    }

    return 0;
}
