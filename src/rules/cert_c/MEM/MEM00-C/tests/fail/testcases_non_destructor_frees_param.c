/*
 * Rule: MEM00-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM00-C violation
 * Description: A function whose name does NOT signal it's a dedicated
 * cleanup/destructor helper still shouldn't free its own parameter as
 * an unexpected side effect (task 318 only excludes destructor-named
 * functions, not this case).
 */

#include <stdlib.h>

int normalize_list(char *list, size_t size) {
    if (size == 0) {
        /* Violation: freeing parameter at wrong abstraction level */
        free(list);
        return -1;
    }
    return 0;
}
