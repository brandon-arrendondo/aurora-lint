/*
 * Rule: INT30-C
 * Source: task 1325 (dev-180's repro; mosquitto fuzzing/ calloc sites)
 * Status: PASS - Should NOT trigger INT30-C violation
 * Reason: The calloc() size-calculation check reported every call that had
 *         no SIZE_MAX / size guard, including ones whose product no input
 *         can reach: `calloc(1, sizeof(struct cfg))` multiplies by one and
 *         `calloc(4, sizeof(struct big))` is an integer constant expression
 *         the compiler folds. Neither is the runtime calculation the
 *         finding describes, so the report was a misfire (ADR-0005). The
 *         proof is by operand range (x0/x1 never wraps; a computed product
 *         in range) or by both operands being compile-time constants --
 *         never by the spelling of the call.
 */

#include <stdlib.h>

#define N_ENTRIES 16

struct cfg { int a; char b[64]; };
struct big { char pad[4096]; };

/* Multiplying by one never wraps, whatever the element size is. */
void *one_struct(void) { return calloc(1, sizeof(struct cfg)); }

/* Both operands are constants: the product is folded, not computed. */
void *four_big(void) { return calloc(4, sizeof(struct big)); }

/* A computed product that fits: 16 * 8. */
void *table(void) { return calloc(N_ENTRIES, sizeof(long)); }

/* Multiplying by one never wraps, even when the count is unknown. */
void *bytes(size_t n) { return calloc(n, 1); }
void *one_of(size_t n) { return calloc(1, n); }

/* A count VRA bounds to [0, 100]: at most 400 bytes. */
void *bounded(int n)
{
    if (n < 0 || n > 100) {
        return NULL;
    }
    return calloc(n, sizeof(int));
}
