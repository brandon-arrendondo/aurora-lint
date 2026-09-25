/*
 * Rule: EXP34-C
 * Status: PASS - the cast allocation is checked and the failure branch calls
 *         exit(), so the pointer passed to `fill` is non-null.
 *
 * A cast does not hide the allocator: `(char *)malloc(n)` may still be NULL.
 * A branch ending in a standard noreturn call leaves as surely as a return,
 * so the check that follows the allocation proves it non-null at the call.
 */

#include <stdlib.h>

static void fill(char *buf)
{
    buf[0] = '\0';
}

void checked_with_exit(void)
{
    char *data;
    data = (char *)malloc(100 * sizeof(char));
    if (data == NULL) {exit(-1);}
    fill(data);
    free(data);
}

void checked_with_abort(void)
{
    char *data = (char *)calloc(10, 1);
    if (!data)
        abort();
    fill(data);
    free(data);
}
