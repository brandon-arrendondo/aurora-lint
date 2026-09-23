/*
 * Rule: MEM30-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: the two guards on crediting a free to a deallocator whose
 * body could not be read past a function-pointer call.
 *
 * ARITY, inherited. The summary only records the escape for a function
 * with exactly ONE parameter, so `ctx_free(ctx, payload)` never carries it
 * and this rule never sees a credit to refuse -- the summary's guard,
 * pinned here from the consuming side. A name says a release happened and
 * never says through WHICH parameter; MEM31-C measured the cost of dropping
 * it, with
 * `Curl_conn_close(data, sockindex)` and `Curl_cwriter_free(data, writer)`
 * reporting curl's `data` double-freed and `Curl_hash_delete(h, key,
 * key_len)` reporting the lookup KEY freed.
 *
 * BY VALUE. An `&var` argument is a claim about the pointee, not the
 * parameter. It stays with `process_address_of_args`, which treats an
 * unknown callee's `&var` as a possible refill and clears the freed state
 * -- so the read after it is not a use of freed memory.
 */

#include <stdlib.h>

struct mem_methods {
    void (*xFree)(void *);
};

struct global_config {
    struct mem_methods m;
};

static struct global_config g_config;

/* Two parameters: which one the name is about is exactly what is unknown. */
void ctx_free(void *ctx, void *payload)
{
    (void)payload;
    g_config.m.xFree(ctx);
}

void amalg_free(void *p)
{
    g_config.m.xFree(p);
}

int context_argument_is_not_the_freed_one(void)
{
    char *ctx = malloc(64);
    char *payload = malloc(64);

    if (ctx == NULL || payload == NULL) {
        return 1;
    }
    ctx_free(ctx, payload);

    /* COMPLIANT: nothing here says the FIRST argument was the released one */
    return payload[0];
}

int address_of_argument_may_refill(void)
{
    char *a = malloc(64);

    if (a == NULL) {
        return 1;
    }
    free(a);
    amalg_free(&a);

    /* COMPLIANT: the callee was handed `a`'s slot and may have refilled it */
    return a[0];
}
