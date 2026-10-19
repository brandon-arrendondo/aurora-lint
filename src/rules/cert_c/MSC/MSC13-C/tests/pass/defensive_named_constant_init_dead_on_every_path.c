/*
 * Rule: MSC13-C
 * Source: mbedtls library/ (real-world regression)
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * `int ret = ERR_CORRUPTION_DETECTED;` is written as fault-injection
 * hardening. Every path from the declaration overwrites `ret` before any
 * read: the CHK macro's `ret = (f)` runs on every path through it, and the
 * early exits return literals. A default value on the declaration that is
 * a constant expression is MSC13-EX1's case: it may be inefficient, but it
 * guards against reading an uninitialized object (EXP33-C).
 */

#define ERR_CORRUPTION_DETECTED -0x006E
#define ERR_BAD_INPUT -0x0004
#define CHK(f) do { if ((ret = (f)) != 0) goto cleanup; } while (0)

int compute(int *out, int x);

int use(int *out, int x)
{
    int ret = ERR_CORRUPTION_DETECTED;

    if (x < 0) {
        return ERR_BAD_INPUT;
    }

    CHK(compute(out, x));
    CHK(compute(out, x + 1));

    ret = 0;

cleanup:
    return ret;
}
