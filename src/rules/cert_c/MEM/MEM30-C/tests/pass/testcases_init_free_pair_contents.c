/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM30-C violation
 */

/*
 * Rule: MEM30-C - Do not access freed memory
 * Status: PASS
 * Reason: `X_free(obj)` after `X_init(obj)` on the same object releases the
 *         object's CONTENTS, not the object. An initializer that was handed
 *         caller-owned storage cannot own that storage, so the paired
 *         name-shaped free does not release the pointer, and the real
 *         `free(p)` that follows is the one and only free of the struct.
 *         mbedtls's init/free convention on a malloc'd struct, as in curl's
 *         lib/vtls/mbedtls.c pinned-pubkey path; the library body is not
 *         available to the scan, so no FunctionSummary can settle it and the
 *         name heuristic used to read the pair as a double free (task 1235).
 */

#include <stdlib.h>
#include <string.h>

typedef struct { void *pk; } crt_t;
void lib_crt_init(crt_t *crt);
void lib_crt_free(crt_t *crt);
int lib_crt_parse(crt_t *crt, const unsigned char *buf, size_t len);

int pin_pubkey(const unsigned char *der, size_t len)
{
    int result = 0;
    crt_t *p = malloc(sizeof(*p));
    if (!p)
        return -1;
    lib_crt_init(p);
    if (lib_crt_parse(p, der, len)) {
        result = -2;
        goto done;
    }
done:
    lib_crt_free(p);   /* contents only */
    free(p);           /* the struct: not a double free */
    return result;
}

/* Same pair through a struct field, and with the init before an early exit. */
struct holder { crt_t *cert; };

int holder_teardown(struct holder *h, int fail)
{
    h->cert = calloc(1, sizeof(*h->cert));
    if (!h->cert)
        return -1;
    lib_crt_init(h->cert);
    if (fail) {
        lib_crt_free(h->cert);
        free(h->cert);
        return -2;
    }
    lib_crt_free(h->cert);
    free(h->cert);
    return 0;
}
