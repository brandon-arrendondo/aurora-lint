/*
 * Rule: DCL13-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL13-C violation
 */

/*
 * Reason: a function-like macro invocation parses as a call_expression, and
 * passing `st[0]` to a real function passes a value -- so the rule rightly
 * does not count `f(st[0])` as a write to `st`. But a macro substitutes the
 * argument text: CHACHA20_QUARTERROUND(st[0], st[4], st[8], st[12]) expands
 * to `st[0] += st[4]; st[12] = ROTL32(...)` and writes `st` on every
 * invocation. The rule now asks macro_expand which parameters the macro
 * body assigns (plain, compound or increment) and treats an element lvalue
 * of the param in such a position as a write (task 1254; real shape from
 * pure-ftpd src/alt_arc4random.c:28, adjudicated as a misfire under task
 * 771 -- ADR-0005: the finding named a "never written" parameter that is
 * written eight times per loop iteration).
 */

#include <stdint.h>

#define ROTL32(x, b) (uint32_t)(((x) << (b)) | ((x) >> (32 - (b))))

#define CHACHA20_QUARTERROUND(A, B, C, D) \
    A += B;                               \
    D = ROTL32(D ^ A, 16);                \
    C += D;                               \
    B = ROTL32(B ^ C, 12);                \
    A += B;                               \
    D = ROTL32(D ^ A, 8);                 \
    C += D;                               \
    B = ROTL32(B ^ C, 7)

/* pure-ftpd shape: every element is only ever written through the macro. */
static void CHACHA20_ROUNDS(uint32_t st[16])
{
    int i;

    for (i = 0; i < 20; i += 2) {
        CHACHA20_QUARTERROUND(st[0], st[4], st[8], st[12]);
        CHACHA20_QUARTERROUND(st[1], st[5], st[9], st[13]);
        CHACHA20_QUARTERROUND(st[2], st[6], st[10], st[14]);
        CHACHA20_QUARTERROUND(st[3], st[7], st[11], st[15]);
        CHACHA20_QUARTERROUND(st[0], st[5], st[10], st[15]);
        CHACHA20_QUARTERROUND(st[1], st[6], st[11], st[12]);
        CHACHA20_QUARTERROUND(st[2], st[7], st[8], st[13]);
        CHACHA20_QUARTERROUND(st[3], st[4], st[9], st[14]);
    }
}

/* Only a compound assignment in the body -- no plain `=` anywhere. */
#define BUMP(x) ((x) += 1)

static void bump_first(unsigned *counts)
{
    BUMP(counts[0]);
}

/* Increment through the macro, on a field of the pointee. */
#define TICK(n) (n)++

struct clock { unsigned ticks; };

static void tick(struct clock *c)
{
    TICK(c->ticks);
}

/* Deref lvalue in a written position. */
#define SET_ZERO(v) ((v) = 0)

static void clear(int *p)
{
    SET_ZERO(*p);
}
