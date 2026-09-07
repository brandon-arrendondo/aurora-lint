/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. A switch carrying a
 * `default` is exhaustive by construction, so when every arm writes through an
 * output parameter, so does every path leaving the switch. Modelled on curl's
 * lib/cw-out.c `cw_get_writefunc`, whose four outputs are each set in all three
 * arms and whose callers were still reported uninitialized (task 1025).
 */
#include <stdio.h>

typedef enum {
    CW_OUT_BODY,
    CW_OUT_BODY_0LEN,
    CW_OUT_HDS
} cw_out_type;

/* Every arm writes both outputs; the stacked labels fall through to the group
   that does. */
static void cw_get_writefunc(cw_out_type otype, size_t *pmax_write,
                             size_t *pmin_write)
{
    switch (otype) {
    case CW_OUT_BODY:
    case CW_OUT_BODY_0LEN:
        *pmax_write = 64;
        *pmin_write = 0;
        break;
    case CW_OUT_HDS:
        *pmax_write = 0;
        *pmin_write = 0;
        break;
    default:
        *pmax_write = 128;
        *pmin_write = 0;
    }
}

void caller(cw_out_type otype)
{
    size_t max_write, min_write;

    cw_get_writefunc(otype, &max_write, &min_write);
    printf("%zu %zu\n", max_write, min_write);
}
