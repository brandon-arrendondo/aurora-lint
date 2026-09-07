/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP33-C violation. Without a `default` label a
 * switch is NOT exhaustive: a value matching no case leaves it having written
 * nothing, so the caller can still read its variable uninitialized. This is the
 * boundary of the exhaustiveness credit added in task 1025 -- the arms here are
 * otherwise identical to the compliant fixture's.
 */
#include <stdio.h>

typedef enum {
    KIND_A,
    KIND_B,
    KIND_C
} kind;

static void maybe_set(kind k, int *out)
{
    switch (k) {
    case KIND_A:
        *out = 1;
        break;
    case KIND_B:
        *out = 2;
        break;
    }
}

void caller(kind k)
{
    int value;

    maybe_set(k, &value);
    printf("%d\n", value);
}
