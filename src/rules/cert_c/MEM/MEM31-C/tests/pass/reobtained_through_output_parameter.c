/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory exactly once
 * Status: PASS
 * Reason: A pointer handed to a callee BY ADDRESS may come back naming a
 *         different block, so the freed mark from its previous release
 *         stops applying to the name. `p = alloc()` already cleared the
 *         mark; `f(&p)` did not, because the name only appears as the
 *         operand of an `&` and the rebind is invisible in the tree. Each
 *         release below is of a distinct block (an earlier fix: hostap's
 *         `IEnumWbemClassObject_Next(..., &pObj, ...)` after an earlier
 *         `_Release`, curl's `Curl_cwriter_create(&writer, ...)` after
 *         `Curl_cwriter_free` on the previous arm).
 */

struct T;

extern int fetch(struct T **out);
extern void ext_free(struct T *);
extern int fetch_many(void *ctx, unsigned long n, struct T **out, unsigned *got);

int reobtain_twice(void)
{
    struct T *p = 0;

    if (fetch(&p) != 0)
        return -1;
    ext_free(p);

    if (fetch(&p) != 0)
        return -1;
    ext_free(p);

    return 0;
}

int reobtain_among_other_arguments(void *ctx)
{
    struct T *obj = 0;
    unsigned got = 0;

    if (fetch_many(ctx, 1, &obj, &got) != 0)
        return -1;
    ext_free(obj);

    if (fetch_many(ctx, 1, &obj, &got) != 0)
        return -1;
    ext_free(obj);

    return 0;
}
