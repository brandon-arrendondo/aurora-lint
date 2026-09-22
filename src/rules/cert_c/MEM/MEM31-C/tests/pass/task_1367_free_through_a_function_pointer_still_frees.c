/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: sqlite's `sqlite3_free(void *p)`, task 1367. Its body
 * releases the block through `sqlite3GlobalConfig.m.xFree(p)` -- a call
 * through a function POINTER, which no summary can follow -- so its
 * `frees_params`, `frees_param_pointees` and `frees_param_fields` are all
 * empty. A summary is trusted over a name shape (task 1128), so that
 * emptiness read as "this `*_free` releases nothing it was handed" and
 * sqlite's one deallocator counted for nothing: the straight-line free
 * below reported a leak at the `return`, and the `goto` reported one
 * because the label's frees were collected through the same predicate.
 *
 * The parameter escaping into an unreadable call is what separates this
 * from mbedtls's `mbedtls_gcm_free(ctx)`, whose body IS readable through
 * and releases nothing -- that one must still refute its name.
 */

#include <stdlib.h>

struct mem_methods {
    void (*xFree)(void *);
};

struct global_config {
    struct mem_methods m;
};

static struct global_config g_config;

void amalg_free(void *p)
{
    if (p == 0) {
        return;
    }
    g_config.m.xFree(p);
}

/* The walk: a plain release through the wrapper, no goto involved. */
int straight_line(void)
{
    char *a = malloc(64);

    if (a == NULL) {
        return 1;
    }
    amalg_free(a);
    return 0;
}

/* The label prescan: every `goto` lands on a label that frees through it. */
int jumps_to_a_label(int cond)
{
    int rc = 0;
    char *a = malloc(64);

    if (a == NULL) {
        return 1;
    }
    if (cond) {
        rc = 2;
        goto decode_out;
    }
    if (cond > 1) {
        rc = 3;
        goto decode_out;
    }
    rc = 4;

decode_out:
    amalg_free(a);
    return rc;
}
